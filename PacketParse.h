/*
 * PacketParse.h
 *
 *  Created on: Aug 2, 2018
 *      Author: root
 */

#ifndef PACKETPARSE_H_
#define PACKETPARSE_H_

#include "RtdbMessage.pb.h"
#include "Log4Cplus.h"
#include "RedisHelper.h"
#include "SemaphoreQueue.h"
#include "ConfigIni.h"
#include "DataSetModel.h"

#include <ber_decode.h>
#include <mms_value.h>
#include <mms_value_internal.h>

#include <boost/lexical_cast.hpp>
#include <boost/thread/thread.hpp>
#include <boost/function.hpp>

#include "pcap.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include <stdio.h>
#include <time.h>
#include <iostream>
#include <vector>
#include <map>
using namespace std;

#define MACLENGTH 14
#define IPLENGTH 20


#define ETH_BUFFER_LENGTH 1518

#define ETH_P_GOOSE 0x88b8

typedef struct{
    int32_t appId; /* APPID or -1 if APPID should be ignored */
    char goCBRef[128];
    uint32_t timeAllowedToLive;
    char dataset[128];
    char goID[128];
    uint32_t stNum;
    uint32_t sqNum;
    uint32_t confRev;
    MmsValue* timestamp;
    bool simulation;
    bool ndsCom;
    uint32_t numberOfDatSetEntries;
    MmsValue* dataSetValues;
    bool dataSetValuesSelfAllocated;
}stGooseContent;


class PacketParse {
public:
	PacketParse();
	virtual ~PacketParse();

	void dissectPacket(string pcapfile, struct pcap_pkthdr *pkthdr, u_char *packet);

	int parseGooseMessage(uint8_t* buffer, unsigned int numbytes, stGooseContent* subscriber);

	int parseGoosePayload(uint8_t* buffer, int apduLength, stGooseContent* self);

	void createNewStringFromBufferElement(MmsValue* value, uint8_t* bufferSrc, int elementLength);

	int parseAllData(uint8_t* buffer, int allDataLength, MmsValue* dataSetValues);

	MmsValue* parseAllDataUnknownValue(stGooseContent* self, uint8_t* buffer, int allDataLength, bool isStructure);

public:
	void analysisGooseContent(stGooseContent self);

	PointValueType getPointValueType(MmsValue*  mmsValue);

	int publishPointValue(stGooseContent self, string fcda, string redisAddr, MmsValue* valueMmsValue, char* utcTime);
public:

	void run();                                        //处理解析完成的报文内容

	void subscribe();                                  //订阅redis，循环获取数据

	void sendHeartBeat();                              //发送心跳

	void start();                                      //开启线程

	void stop();

private:


	RedisHelper *redisHelper;
	RedisHelper *heatRedisHelper;                 //发送心跳 redis

	SemaphoreQueue<stGooseContent> queGooseContent;

	bool isRunning;

	DataSetModel dataSetModel;

	string pcapFile;
};

#endif /* PACKETPARSE_H_ */
