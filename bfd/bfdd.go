package main

// #include "bfdd.h"
// #cgo LDFLAGS: -L ./ -lbfdd
//void callOnMeGo_cgo(BFD_RSP *val);
//void logCallOnMeGo_cgo(char *val);
import "C"

import (
	"config"
	"encoding/json"
	"flag"
	"fmt"
	"nrpc"
	"os"
	"os/signal"
	"runtime/debug"
	log "slog"
	"sync"
	"syscall"
	"system"
	"time"
	"unsafe"

	"github.com/nats-io/go-nats"
)

//BFD 控制块
type Manager struct {
	sync.RWMutex

	//RPC
	RPC *nrpc.Rpc

	//新BFD会话配置
	BFDSession map[string]nrpc.BFDSessionCfg

	//旧的BFD会话配置
	OldBFDSession map[string]nrpc.BFDSessionCfg

	//BFD会话状态
	BFDSessionState map[string]string

	//BFD服务类型， 如果是HA bfd则为真，如果是业务BFD则为假
	BFDServiceType map[string]bool
}

const (
	//BFD会话up消息
	BFDSessionUp string = "BFDSessionUp"

	//BFD会话dwon消息
	BFDSessionDown string = "BFDSessionDown"

	//BFD会话删除消息
	BFDSessionDelete string = "BFDSessionDelete"
)

//c字符数组转go字符串
func cchararray2gostring(src []C.char) string {
	if len(src) == 0 {
		return ""
	}
	count := len(src) - 1

	dst := make([]byte, 0)

	for i := 0; i < count && src[i] != 0; i++ {
		dst = append(dst, byte(src[i]))
	}

	return string(dst)
}

//go字符串转换成c无符号字节数组
func gostring2cubyte(dst []C.uchar, src string) {
	if len(dst) == 0 {
		return
	}

	count := len(dst) - 1

	if count > len(src) {
		count = len(src)
	}

	for i := 0; i < count; i++ {
		dst[i] = C.uchar(src[i])
	}

	dst[count] = 0
}

// go 字符串转换c有符号字节数组
func gostring2cbyte(dst []C.char, src string) {
	if len(dst) == 0 {
		return
	}

	count := len(dst) - 1

	if count > len(src) {
		count = len(src)
	}

	for i := 0; i < count; i++ {
		dst[i] = C.char(src[i])
	}

	dst[count] = 0
}

// go 字节数组转换成c字节数组
func gobyte2cbyte(dst []C.char, src []byte) {
	if len(dst) == 0 {
		return
	}

	count := len(dst) - 1

	if count > len(src) {
		count = len(src)
	}

	for i := 0; i < count; i++ {
		dst[i] = C.char(src[i])
	}

	dst[count] = 0
}

// go的回调函数，传递给C库

//export bfdLogCallback
func bfdLogCallback(info *C.char) {
	log.Debug(C.GoString(info))
}

//通知上层回调函数

//export bfdCallback
func bfdCallback(val *C.BFD_RSP) {
	Msg := nrpc.BFDSessionMsg{}
	switch int(val.msgtype) {

	//BFD会话up
	case C.BFDSessionUp:
		Msg.MsgType = BFDSessionUp

	//BFD会话down
	case C.BFDSessionDown:
		Msg.MsgType = BFDSessionDown
		Msg.MsgInfo = cchararray2gostring(val.msginfo[:])

	//BFD会话delete
	case C.BFDSessionDelete:
		Msg.MsgType = BFDSessionDelete
	}

	//会话key值
	Msg.MsgKey = cchararray2gostring(val.msgkey[:])

	//更新BFD会话表状态
	BfdMng.Lock()
	Msg.MsgServiceType = BfdMng.BFDServiceType[Msg.MsgKey]
	BfdMng.BFDSessionState[Msg.MsgKey] = Msg.MsgType
	BfdMng.Unlock()

	//编码BFD消息
	data, err := json.Marshal(&Msg)
	if nil != err {
		fmt.Printf("PubBFDSession json.Marshal BFDMsg fail! MsgErr:%s.",
			err.Error())
		return
	}

	// 发布RPC信息
	log.Info("BFD Publish Event %s", Msg.MsgType)
	BfdMng.RPC.Publish(system.SetMasterPrefix("BFD.Event.StateInfo"), data)
}

func recordPainc(perr interface{}) {
	f, nerr := os.OpenFile("/etc/sbcerr", os.O_APPEND|os.O_CREATE, 0)
	if nil != nerr {
		f.WriteString("-------bfd backtrace start--------")
		f.WriteString(fmt.Sprintf("-------time:%s------", time.Now().String()))
		if nil != perr {
			f.WriteString(fmt.Sprint(perr))
		}
		f.Write(debug.Stack())
		f.WriteString("-------bfd backtrace end--------")
		f.Close()
	}
}

//BfdPubBFDSession 下发配置
func (BfdMng *Manager) BFDConfigDispatch() {

	//获取bfd配置
	config.GetBFDCfg(BfdMng.BFDSession)
	log.Info("BfdConfigDispatch:BFDSession:%v.", BfdMng.BFDSession)

	if 0 == len(BfdMng.OldBFDSession) {
		for Key, Value := range BfdMng.BFDSession {
			//设置会话初始状态
			BfdMng.BFDSessionState[Key] = BFDSessionDown

			//设置服务类型，HA为true或者业务为false
			BfdMng.BFDServiceType[Key] = Value.BfdServiceType

			//复制一份到旧的会话表
			BfdMng.OldBFDSession[Key] = Value

			//创建会话
			log.Info("BFD add new session, Key: %s", Key)
			BfdAddSession(Key, Value)
		}
	} else {
		//遍历旧会话表，找出新会话表不存在的会话并删除
		for Key, Value := range BfdMng.OldBFDSession {
			if _, ok := BfdMng.BFDSession[Key]; ok {
				//存在会话不处理
			} else {
				//删除会话
				BfdDeleteSession(Value)

				//删除会话状态
				delete(BfdMng.BFDSessionState, Key)

				//删除服务类型
				delete(BfdMng.BFDServiceType, Key)

				//发布会话删除事件
				Msg := nrpc.BFDSessionMsg{}
				Msg.MsgType = BFDSessionDelete
				Msg.MsgKey = Key
				Msg.MsgServiceType = Value.BfdServiceType

				//编码BFD消息
				data, err := json.Marshal(&Msg)
				if nil != err {
					fmt.Printf("PubBFDSession json.Marshal BFDMsg fail! MsgErr:%s.", err.Error())
					return
				}

				// 发布RPC信息
				BfdMng.RPC.Publish(system.SetMasterPrefix("BFD.Event.StateInfo"), data)
			}
		}
		//遍历新会话表，找出旧会话表不存在的表项并新建会话
		for Key, Value := range BfdMng.BFDSession {
			if _, ok := BfdMng.OldBFDSession[Key]; ok {
				//存在不处理
			} else {
				//初始化会话状态
				BfdMng.BFDSessionState[Key] = BFDSessionDown

				//复制一份到旧的会话表
				BfdMng.OldBFDSession[Key] = Value

				//设置服务类型，HA或者业务
				BfdMng.BFDServiceType[Key] = Value.BfdServiceType

				//新建会话
				log.Info("BFD add session, Key: %s", Key)
				BfdAddSession(Key, Value)
			}
		}
	}
}

//BfdCfgRefreshCallBack BFD配置更新回调函数
func BfdCfgRefreshCallBack() {
	BfdMng.Lock()
	defer BfdMng.Unlock()

	//BFD进程启动，则配置BFD会话
	log.Info("BFD Config Refresh")
	BfdMng.BFDConfigDispatch()
}

//BfdMng 全局管理数据结构
var BfdMng *Manager

func BfdHBProc() {
	go func() {
		BfdTimeHdl := time.NewTimer(time.Duration(5) * time.Second)
		for {
			select {
			case <-BfdTimeHdl.C:
				BfdHBMsg := nrpc.ServiceHeartBeat{}
				BfdHBMsg.ServiceName = "BFDD"
				BfdHBMsg.ServicePID = os.Getpid()

				data, err := json.Marshal(BfdHBMsg)
				if nil != err {
					log.Err("BFD SendHeartBeat, json.Marshal  fail! err:%s.",
						err.Error())
					return
				}

				log.Debug("BFD SendHeartBeat, Publish  ServiceHeartBeat OK. Service:%s.================", BfdHBMsg.ServiceName)
				// 发布bfdd心跳
				BfdMng.RPC.Publish(system.SetMasterPrefix("Ha.Event.ServiceHeartBeat"), data)
				BfdTimeHdl.Reset(time.Duration(2) * time.Second)
			}
		}
	}()
}

//BfdMngInit BFD管理控制块初始化
func BfdMngInit() error {
	BfdMng = &Manager{}

	//初始化rpc池
	log.Info("BFD Init RPC")
	system.GetMasterPrefix()
	rpcurl := system.GetLocalBoardRpcUrl(system.GetLocalBoardId())
	err := nrpc.Init(rpcurl, 50, 10*time.Second)
	if nil != err {
		log.Err("****Init BFD RPC Pool fail****")
		return err
	}

	//创建订阅连接RPC
	rpc, err := nrpc.NewRpc()
	if nil != err {
		log.Err("****BFD NewRpc fail:%s****", err.Error())
		return err
	}

	log.Info("BFD Manager start, new rpc success. ")

	BfdMng.RPC = rpc

	//会话控制块初始化
	BfdMng.BFDSession = make(map[string]nrpc.BFDSessionCfg)

	//会话控制块初始化
	BfdMng.OldBFDSession = make(map[string]nrpc.BFDSessionCfg)

	//会话状态控制块初始化
	BfdMng.BFDSessionState = make(map[string]string)

	//会话服务类型初始化
	BfdMng.BFDServiceType = make(map[string]bool)

	return nil
}

//删除bfd会话
func BfdDeleteSession(BFDSession nrpc.BFDSessionCfg) {
	cVal := C.BFD_CFG{}
	cVal.localPort = C.ushort(BFDSession.LocalPort)
	cVal.remotePort = C.ushort(BFDSession.RemotePort)
	gostring2cubyte(cVal.localIP[:], BFDSession.LocalIP)
	gostring2cubyte(cVal.remoteIP[:], BFDSession.RemoteIP)

	C.bfd_delete(&cVal)
}

//添加bfd会话
func BfdAddSession(BfdSessionkey string, BFDCfgData nrpc.BFDSessionCfg) {
	cVal := C.BFD_CFG{}
	cVal.localIPType = C.uint(BFDCfgData.LocalIPType)
	cVal.localPort = C.ushort(BFDCfgData.LocalPort)
	cVal.remoteIPType = C.uint(BFDCfgData.RemoteIPType)
	cVal.remotePort = C.ushort(BFDCfgData.RemotePort)
	gostring2cubyte(cVal.localIP[:], BFDCfgData.LocalIP)
	gostring2cubyte(cVal.remoteIP[:], BFDCfgData.RemoteIP)
	cVal.detectMult = C.uint(BFDCfgData.DetectMult)
	cVal.desMinTx = C.uint(BFDCfgData.DesiredMinTx)
	cVal.reqMinRx = C.uint(BFDCfgData.RequiredMinRx)
	cVal.reqMinEchoRx = C.uint(BFDCfgData.RequiredEchoMinRx)
	//cVal.serviceType = C.uchar(BFDCfgData.BfdServiceType)

	gostring2cbyte(cVal.key[:], BfdSessionkey)

	C.bfd_add(&cVal)
}

func main() {
	//配置log 日志
	level := flag.Int("l", 7, "log level[-1:disble,0:emerg,1:alert,2:crit,3:err,4:warning,5:notice,6:info,7:debug,8:trace],default:-1")
	console := flag.Bool("c", false, "log out to console")
	syncLog := flag.Bool("s", false, "synchronize process log")

	flag.Parse()

	logger := log.GetLogger()

	logger.SetLogLevel(log.Level(*level))

	if *console {
		logger.SetFlag(log.LConsole)
	}

	if *syncLog {
		logger.SetFlag(log.LSyncOut)
	}

	//初始化BFD管理器
	err := BfdMngInit()
	if nil != err {
		log.Err("****************BFD mng init fail! err:%s.", err.Error())
		return
	}

	//设置库回调函数
	log.Debug("BFD init, set callback")
	C.bfd_setCallback((C.CALLBACK_FUNC)(unsafe.Pointer(C.callOnMeGo_cgo)))
	C.bfd_setLogCallback((C.LOG_CALLBACK_FUNC)(unsafe.Pointer(C.logCallOnMeGo_cgo)))

	//bfd初始化
	ret := C.bfd_init()
	if ret != 0 {
		log.Info("*************BFD init fail")
		return
	}

	//读取BFD配置文件信息并注册配置文件刷新回调函数
	ConfigErr := config.InitBfdCfg(BfdCfgRefreshCallBack)
	if nil != ConfigErr {
		log.Err("*************InitBfdCfg fail:%s", ConfigErr.Error())
	} else {
		log.Info("InitBfdCfg success.")
	}

	//bfd心跳线程
	//测试的时候先关闭
	//BfdHBProc()

	// 订阅BFD查询消息
	BfdMng.RPC.Subscribe(system.SetMasterPrefix("BFD.Event.GetInfo"), func(msg *nats.Msg) {

		BfdMng.Lock()
		//查询状态表
		for Key, Value := range BfdMng.BFDSessionState {
			Msg := nrpc.BFDSessionMsg{}
			Msg.MsgType = Value
			Msg.MsgKey = Key
			Msg.MsgServiceType = BfdMng.BFDServiceType[Key]

			//编码BFD消息
			data, err := json.Marshal(&Msg)
			if nil != err {
				log.Err("PubBFDSession json.Marshal BFDMsg fail! MsgErr:%s.", err.Error())
				return
			}

			// 发布RPC信息
			BfdMng.RPC.Publish(system.SetMasterPrefix("BFD.Event.StateInfo"), data)
		}
		BfdMng.Unlock()
	})

	chSignal := make(chan os.Signal, 5)
	//signal.Notify(chSignal)
	//监听指定信号
	signal.Notify(chSignal, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT,
		syscall.SIGSEGV, syscall.SIGABRT)

	log.Info("All BFD init finished, start run BFD")

	//阻塞直至有信号传入
	sig := <-chSignal
	switch sig {
	case syscall.SIGSEGV, syscall.SIGABRT:
		recordPainc(nil)
	default:
		log.Info("*************BFD Receive signal %s\n", sig.String())
	}
	C.bfd_exit()
	log.Info("*************BFD Recive signal %s, program exit", sig.String())

	time.After(1 * time.Second)
}
