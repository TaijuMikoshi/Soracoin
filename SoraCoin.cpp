// SoraCoin.cpp : 
//
#ifdef _WIN32
#include <direct.h>
#endif

#include <sys/stat.h>

#include <iostream>

#include <signal.h>

#include "Node.h"
#include "Params.h"
#include "Status.h"
#include "Log.h"
#include "UpnpNatTraversal.h"

Logging mylog;

const std::string walletDirPath("./wallet");
const std::string confDirPath("./config");
const std::string logDirPath("./log");

const std::string configFile = confDirPath + "/conf.txt";
const std::string logFile = logDirPath + "/error.log";
const std::string walletFile = walletDirPath + "/wallet.txt";
const std::string peerInfoFile = confDirPath + "/peer.txt";
const std::string blockFileDirPath = walletDirPath;

Node node;
ThreadStopFlag stopFlag;
Parameters param;

bool checkDirectory(const std::string& path) {
  struct stat statBuf;

  if (stat(path.c_str(), &statBuf) != 0) {
#ifdef _WIN32
    if (_mkdir(path.c_str()) != 0) { return false;}
#else
    if (mkdir(path.c_str(), S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0) { return false; }
#endif
  }
  return true;
}

bool initApp(Parameters& param) {
  if (!checkDirectory(walletDirPath)) return false;
  if (!checkDirectory(confDirPath)) return false;
  if (!checkDirectory(logDirPath)) return false;

  mylog = Logging(logFile);
  if (!mylog) {
    std::cerr << logFile << " open error. Please check permission";
    return false;
  }

  if (param.LoadConfig(configFile) != ResultStatus::ALL_CORRECT) {
    std::cerr << configFile << " open error. Pleas check the file.";
    return false;
  }

  UpnpNatTraversal upnp;

  upnp.searchWANIPConnection();

  param.setGlobalIpAddress(upnp.GetExternalIPAddress());
  param.setLocalIpAddress(upnp.getLocalIP());

  const std::string localIP = upnp.getLocalIP();

  std::stringstream iternalPort;
  iternalPort << param.listenPort();
  int port = param.listenPort();
  for (int i = 0; i < param.MAX_UNPN_COUNT; i++) {
    std::stringstream ex;
    ex << port;
    if (upnp.AddPortMapping(localIP, iternalPort.str(), ex.str())) {
      break;
    };
    port = param.listenPort() + i+1;
  }

  if (port >= param.listenPort() + param.MAX_UNPN_COUNT) {
    return false;
  }

  Block::initScriptExcec();

  return true;
}

void sighandler(int sig) {
  printf("please wait to terminate program...");

  node.stopSignal();
  stopFlag.signal();

  UpnpNatTraversal upnp;
  upnp.searchWANIPConnection();

  std::stringstream ss;
  ss << param.externalPort();
  upnp.DeletePortMapping(ss.str());
}

int main()
{
  signal(SIGINT, sighandler);

  if (!initApp(param)) { return ResultStatus::INIT_ERROR;}

  if (node.init(walletFile, peerInfoFile, param, blockFileDirPath) != ResultStatus::ALL_CORRECT) {
    return ResultStatus::FAILED;
  }

  node.serverStart();
  node.clientStart();
  node.minigStart();

  char t;
  while (!stopFlag) {
#ifdef _WIN32
    system("cls");
#else
    auto ret = system("clear");
#endif
    std::cout << "Current Block Height : " << node.getBlockHeight() << std::endl;
    std::cout << "Watting to RPC method at port# " << param.listenPort() << std::endl;
    
    const int sleepTime = 1000;
#ifdef _WIN32
    Sleep(sleepTime);
#else
    sleep(sleepTime / 1000);
#endif
  }

  node.waitToStopServer();
  node.waitToStopClient();
  node.waitToStopMinig();

  return ResultStatus::ALL_CORRECT;
}
