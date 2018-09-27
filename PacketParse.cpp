/*
 * PacketParse.cpp
 *
 *  Created on: Aug 2, 2018
 *      Author: root
 */

#include "PacketParse.h"

PacketParse::PacketParse() {
	isRunning = true;
	queGooseContent.set_size(100000);

	start();

	if(dataSetModel.load("/home/GM2000/" + SingletonConfig->getDatasetFilePath()))
	{
		SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "Load datasetfile Success:/home/GM2000/" + SingletonConfig->getDatasetFilePath());
	}
	else
	{
		SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_WARN, "Load datasetfile Failure:/home/GM2000/" + SingletonConfig->getDatasetFilePath());
	}
}

PacketParse::~PacketParse() {
	// TODO Auto-generated destructor stub
}

void PacketParse::dissectPacket(string pcapfile, struct pcap_pkthdr *pkthdr, u_char *packet)
{
	stGooseContent gooseContent;
	memset(&gooseContent, 0, sizeof(stGooseContent));

	parseGooseMessage(packet, pkthdr->len, &gooseContent);

	queGooseContent.push_back(gooseContent);
}

int PacketParse::parseGooseMessage(uint8_t* buffer, unsigned int numbytes, stGooseContent* subscriber)
{
    int bufPos;

    if (numbytes < 22) return -1;

    /* skip ethernet addresses */
    bufPos = 12;
    int headerLength = 14;

    /* check for VLAN tag */
    if ((buffer[bufPos] == 0x81) && (buffer[bufPos + 1] == 0x00)) {
        bufPos += 4; /* skip VLAN tag */
        headerLength += 4;
    }

    /* check for GOOSE Ethertype */
    if (buffer[bufPos++] != 0x88)
        return -1;
    if (buffer[bufPos++] != 0xb8)
        return -1;

    uint16_t appId;

    appId = buffer[bufPos++] * 0x100;
    appId += buffer[bufPos++];

    uint16_t length;

    length = buffer[bufPos++] * 0x100;
    length += buffer[bufPos++];

    /* skip reserved fields */
    bufPos += 4;

    int apduLength = length - 8;

    if (numbytes != length + headerLength) {
    	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "Invalid PDU size");
        return -1;
    }

    SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, "GOOSE message:");
    SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, "  APPID: " + boost::lexical_cast<string>(appId));
    SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, "  LENGTH: " + boost::lexical_cast<string>(length));
    SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, "  APDU length: " + boost::lexical_cast<string>(apduLength));

    return parseGoosePayload(buffer + bufPos, apduLength, subscriber);
}

int PacketParse::parseGoosePayload(uint8_t* buffer, int apduLength, stGooseContent* self)
{
    int bufPos = 0;

    if (buffer[bufPos++] == 0x61) {
        int gooseLength;
        bufPos = BerDecoder_decodeLength(buffer, &gooseLength, bufPos, apduLength);

        int gooseEnd = bufPos + gooseLength;

        while (bufPos < gooseEnd) {
            int elementLength;

            uint8_t tag = buffer[bufPos++];
            bufPos = BerDecoder_decodeLength(buffer, &elementLength, bufPos, apduLength);

            if (bufPos + elementLength > apduLength) {
            	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, "Malformed message: sub element is to large!");
                goto exit_with_fault;
            }

            if (bufPos == -1)
                goto exit_with_fault;

            switch(tag) {
            case 0x80: /* gocbRef */
				memcpy(self->goCBRef, buffer + bufPos, elementLength);
				SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, string("  Found gocbRef :") + self->goCBRef);
                break;

            case 0x81: /* timeAllowedToLive */
            	self->timeAllowedToLive = BerDecoder_decodeUint32(buffer, elementLength, bufPos);
            	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, string("  Found timeAllowedToLive:") + boost::lexical_cast<string>(self->timeAllowedToLive));
                break;

            case 0x82:
            	memcpy(self->dataset, buffer + bufPos, elementLength);
            	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, string("  Found dataSet :") + self->dataset);
                break;

            case 0x83:
            	memcpy(self->goID, buffer + bufPos, elementLength);
            	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, string("  Found goId :") + self->goID);
                break;

            case 0x84:
            	self->timestamp = MmsValue_newUtcTime(0);
                MmsValue_setUtcTimeByBuffer(self->timestamp, buffer + bufPos);
                SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, string("  Found timestamp t:") + boost::lexical_cast<string>(MmsValue_getUtcTimeInMs(self->timestamp)));
                break;

            case 0x85:
            	self->stNum = BerDecoder_decodeUint32(buffer, elementLength, bufPos);
            	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, string("  Found stNum: ") + boost::lexical_cast<string>(self->stNum));
                break;

            case 0x86:
            	self->sqNum = BerDecoder_decodeUint32(buffer, elementLength, bufPos);
            	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, string("  Found sqNum: ") + boost::lexical_cast<string>(self->sqNum));
                break;

            case 0x87:
            	self->simulation = BerDecoder_decodeBoolean(buffer, bufPos);
            	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, string("  Found simulation: ") + boost::lexical_cast<string>(self->simulation));
                break;

            case 0x88:
            	self->confRev = BerDecoder_decodeUint32(buffer, elementLength, bufPos);
            	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, string("  Found confRev: ") + boost::lexical_cast<string>(self->confRev));
                break;

            case 0x89:
            	self->ndsCom = BerDecoder_decodeBoolean(buffer, bufPos);
            	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, string("  Found ndsCom: ") + boost::lexical_cast<string>(self->ndsCom));
                break;

            case 0x8a:
            	self->numberOfDatSetEntries = BerDecoder_decodeUint32(buffer, elementLength, bufPos);
            	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, string("  Found number of entries: ") + boost::lexical_cast<string>(self->numberOfDatSetEntries));
                break;

            case 0xab:
            	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, string("  Found all data with length: ") + boost::lexical_cast<string>(elementLength));

                if (self->dataSetValues == NULL)
                    self->dataSetValues = parseAllDataUnknownValue(self, buffer + bufPos, elementLength, false);
                else
                    parseAllData(buffer + bufPos, elementLength, self->dataSetValues);
                break;

            default:
            	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, string("  Unknown tag :") + boost::lexical_cast<string>(tag));
                break;
            }

            bufPos += elementLength;
        }
        return 0;
    }

exit_with_fault:
    if (DEBUG)
    	printf("Invalid goose payload\n");
    return -1;
}



void PacketParse::createNewStringFromBufferElement(MmsValue* value, uint8_t* bufferSrc, int elementLength)
{
    value->value.visibleString.buf = (char*) malloc(elementLength + 1);
    memcpy(value->value.visibleString.buf, bufferSrc, elementLength);
    value->value.visibleString.buf[elementLength] = 0;
    value->value.visibleString.size = elementLength;
}

int PacketParse::parseAllData(uint8_t* buffer, int allDataLength, MmsValue* dataSetValues)
{
    int bufPos = 0;
    int elementLength = 0;

    int elementIndex = 0;

    int maxIndex = MmsValue_getArraySize(dataSetValues) - 1;

    while (bufPos < allDataLength) {
        uint8_t tag = buffer[bufPos++];

        if (elementIndex > maxIndex) {
        	if (DEBUG) printf("Malformed message: too much elements!\n");
        	return 0;
        }

        MmsValue* value = MmsValue_getElement(dataSetValues, elementIndex);

        bufPos = BerDecoder_decodeLength(buffer, &elementLength, bufPos, allDataLength);

        if (bufPos + elementLength > allDataLength) {
            if (DEBUG) printf("Malformed message: sub element is to large!\n");
            return 0;
        }

        switch (tag) {
        case 0x80: /* reserved for access result */
            printf("    found reserved value (tag 0x80)!\n");
            break;
        case 0xa1: /* array */
            if (DEBUG) printf("    found array\n");
            if (MmsValue_getType(value) == MMS_ARRAY) {
            	if (!parseAllData(buffer + bufPos, elementLength, value))
            		return -1;
            }
            break;
        case 0xa2: /* structure */
            if (DEBUG) printf("    found structure\n");
            if (MmsValue_getType(value) == MMS_STRUCTURE) {
				if (!parseAllData(buffer + bufPos, elementLength, value))
					return -1;
			}
            break;
        case 0x83: /* boolean */
            if (DEBUG) printf("    found boolean\n");

            if (MmsValue_getType(value) == MMS_BOOLEAN) {
                MmsValue_setBoolean(value, BerDecoder_decodeBoolean(buffer, bufPos));
            }
            else
                if (DEBUG) printf("      message contains value of wrong type!\n");

            break;

        case 0x84: /* BIT STRING */
        	if (MmsValue_getType(value) == MMS_BIT_STRING) {
        		int padding = buffer[bufPos];
        		int bitStringLength = (8 * (elementLength - 1)) - padding;
        		if (bitStringLength == value->value.bitString.size) {
        			memcpy(value->value.bitString.buf, buffer + bufPos + 1,
        					elementLength - 1);
        		}
        		else
        			printf("bit-string is of wrong size");
        	}
        	break;
        case 0x85: /* integer */
        	if (MmsValue_getType(value) == MMS_INTEGER) {
        		if (elementLength <= value->value.integer->maxSize) {
        			value->value.integer->size = elementLength;
        			memcpy(value->value.integer->octets, buffer + bufPos, elementLength);
        		}
        	}
        	break;
        case 0x86: /* unsigned integer */
        	if (MmsValue_getType(value) == MMS_UNSIGNED) {
				if (elementLength <= value->value.integer->maxSize) {
					value->value.integer->size = elementLength;
					memcpy(value->value.integer->octets, buffer + bufPos, elementLength);
				}
			}
			break;
        case 0x87: /* Float */
        	if (MmsValue_getType(value) == MMS_FLOAT) {
				if (elementLength == 9) {
					MmsValue_setDouble(value, BerDecoder_decodeDouble(buffer, bufPos));
				}
				else if (elementLength == 5) {
					MmsValue_setFloat(value, BerDecoder_decodeFloat(buffer, bufPos));
				}
        	}
        	break;

        case 0x89: /* octet string */
        	if (MmsValue_getType(value) == MMS_OCTET_STRING) {
        		if (elementLength <= value->value.octetString.maxSize) {
        			value->value.octetString.size = elementLength;
        			memcpy(value->value.octetString.buf, buffer + bufPos, elementLength);
        		}
        	}
        	break;
        case 0x8a: /* visible string */
        	if (MmsValue_getType(value) == MMS_VISIBLE_STRING) {

        		if (value->value.visibleString.buf != NULL) {
        			if ((int32_t) value->value.visibleString.size >= elementLength) {
        				memcpy(value->value.visibleString.buf, buffer + bufPos, elementLength);
						value->value.visibleString.buf[elementLength] = 0;
        			}
        			else {
        				free(value->value.visibleString.buf);

        				createNewStringFromBufferElement(value, buffer + bufPos, elementLength);
        			}
        		}
        		else
        		    createNewStringFromBufferElement(value, buffer + bufPos, elementLength);

        	}
        	break;
        case 0x8c: /* binary time */
        	if (MmsValue_getType(value) == MMS_BINARY_TIME) {
        		if ((elementLength == 4) || (elementLength == 6)) {
        			memcpy(value->value.binaryTime.buf, buffer + bufPos, elementLength);
        		}
        	}
        	break;
        case 0x91: /* Utctime */
            if (elementLength == 8) {
                if (MmsValue_getType(value) == MMS_UTC_TIME) {
                    MmsValue_setUtcTimeByBuffer(value, buffer + bufPos);
                }
                else
                    if (DEBUG) printf("      message contains value of wrong type!\n");
            }
            else
                if (DEBUG) printf("      UTCTime element is of wrong size!\n");
            break;
        default:
            printf("    found unkown tag %02x\n", tag);
            break;
        }

        bufPos += elementLength;

        elementIndex++;
    }

    return 1;
}

MmsValue* PacketParse::parseAllDataUnknownValue(stGooseContent* self, uint8_t* buffer, int allDataLength, bool isStructure)
{
    int bufPos = 0;
    int elementLength = 0;

    int elementIndex = 0;

    MmsValue* dataSetValues = NULL;

    while (bufPos < allDataLength) {
        uint8_t tag = buffer[bufPos++];

        bufPos = BerDecoder_decodeLength(buffer, &elementLength, bufPos, allDataLength);

        if (bufPos + elementLength > allDataLength) {
            if (DEBUG) printf("Malformed message: sub element is to large!\n");
            goto exit_with_error;
        }

        switch (tag) {
        case 0x80: /* reserved for access result */
            break;
        case 0xa1: /* array */
            break;
        case 0xa2: /* structure */
            break;
        case 0x83: /* boolean */
            break;
        case 0x84: /* BIT STRING */
            break;
        case 0x85: /* integer */
            break;
        case 0x86: /* unsigned integer */
            break;
        case 0x87: /* Float */
            break;
        case 0x89: /* octet string */
            break;
        case 0x8a: /* visible string */
            break;
        case 0x8c: /* binary time */
            break;
        case 0x91: /* Utctime */
            break;
        default:
            printf("    found unkown tag %02x\n", tag);
            goto exit_with_error;
        }

        bufPos += elementLength;

        elementIndex++;
    }

    if (isStructure)
        dataSetValues = MmsValue_createEmptyStructure(elementIndex);
    else
        dataSetValues = MmsValue_createEmtpyArray(elementIndex);

    elementIndex = 0;
    bufPos = 0;

    while (bufPos < allDataLength) {
        uint8_t tag = buffer[bufPos++];

        bufPos = BerDecoder_decodeLength(buffer, &elementLength, bufPos, allDataLength);

        if (bufPos + elementLength > allDataLength) {
            if (DEBUG) printf("Malformed message: sub element is too large!\n");
            goto exit_with_error;
        }

        MmsValue* value = NULL;

        switch (tag) {
        case 0xa1: /* array */
            if (DEBUG) printf("    found array\n");

            value = parseAllDataUnknownValue(self, buffer + bufPos, elementLength, false);

            if (value == NULL)
                goto exit_with_error;

            break;
        case 0xa2: /* structure */
            if (DEBUG) printf("    found structure\n");

            value = parseAllDataUnknownValue(self, buffer + bufPos, elementLength, true);

            if (value == NULL)
                goto exit_with_error;

            break;
        case 0x83: /* boolean */
            if (DEBUG) printf("    found boolean\n");
            value = MmsValue_newBoolean(BerDecoder_decodeBoolean(buffer, bufPos));

            break;

        case 0x84: /* BIT STRING */
            {
                int padding = buffer[bufPos];
                int bitStringLength = (8 * (elementLength - 1)) - padding;
                value = MmsValue_newBitString(bitStringLength);
                memcpy(value->value.bitString.buf, buffer + bufPos + 1, elementLength - 1);

            }
            break;
        case 0x85: /* integer */
            value = MmsValue_newInteger(elementLength * 8);
            memcpy(value->value.integer->octets, buffer + bufPos, elementLength);
            break;
        case 0x86: /* unsigned integer */
            value = MmsValue_newUnsigned(elementLength * 8);
            memcpy(value->value.integer->octets, buffer + bufPos, elementLength);
            break;
        case 0x87: /* Float */
                if (elementLength == 9)
                    value = MmsValue_newDouble(BerDecoder_decodeDouble(buffer, bufPos));
                else if (elementLength == 5)
                    value = MmsValue_newFloat(BerDecoder_decodeFloat(buffer, bufPos));
            break;

        case 0x89: /* octet string */
            value = MmsValue_newOctetString(elementLength, elementLength);
            memcpy(value->value.octetString.buf, buffer + bufPos, elementLength);
            break;
        case 0x8a: /* visible string */
            value = MmsValue_newVisibleStringFromByteArray(buffer + bufPos, elementLength);
            break;
        case 0x8c: /* binary time */
            if (elementLength == 4)
                value = MmsValue_newBinaryTime(true);
            else if (elementLength == 6)
                value = MmsValue_newBinaryTime(false);

            if ((elementLength == 4) || (elementLength == 6))
                memcpy(value->value.binaryTime.buf, buffer + bufPos, elementLength);

            break;
        case 0x91: /* Utctime */
            if (elementLength == 8) {
                value = MmsValue_newUtcTime(0);
                MmsValue_setUtcTimeByBuffer(value, buffer + bufPos);
            }
            else
                if (DEBUG) printf("      UTCTime element is of wrong size!\n");
            break;
        default:
            if (DEBUG) printf("    found unkown tag %02x\n", tag);
            goto exit_with_error;
        }

        bufPos += elementLength;

        if (value != NULL) {
            MmsValue_setElement(dataSetValues, elementIndex, value);
            elementIndex++;
        }
    }

    self->dataSetValuesSelfAllocated = true;

    return dataSetValues;

exit_with_error:

    if (dataSetValues != NULL)
        MmsValue_delete(dataSetValues);

    return NULL;
}


void PacketParse::analysisGooseContent(stGooseContent self)
{
	vector<string> vecFcd = dataSetModel.getFcdByDataset(self.dataset);
	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, string("dataset:") + self.dataset +
							" size:" + boost::lexical_cast<string>(vecFcd.size()) +
							" numberOfDatSetEntries:" + boost::lexical_cast<string>(self.numberOfDatSetEntries));
	int elementIndex = 0;
	int maxElementIndex = MmsValue_getArraySize(self.dataSetValues);
	while(elementIndex < maxElementIndex)
	{
		string fcd = vecFcd.at(elementIndex);
		vector<string> vecFcda = dataSetModel.getFcdaByFcd(fcd);                               //通过FCD获取FCD中的每个数据引用
		string fcda = vecFcda.at(0);
		string redisAddr = SingletonConfig->getPubAddrByFcda(fcda);
		MmsValue* value = MmsValue_getElement(self.dataSetValues, elementIndex);
		char strMmsvalue[64] = {0};
		SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, string(MmsValue_getTypeString(value)) + " " +
								fcda + " " + redisAddr + " " +
							   MmsValue_printToBuffer(value, strMmsvalue, 64));
		elementIndex++;
	}

	MmsValue_deleteIfNotNull(self.timestamp);
	MmsValue_deleteIfNotNull(self.dataSetValues);
}

int PacketParse::publishPointValue(stGooseContent self, string fcda, string redisAddr, MmsValue*  fcdaMmsValue, char* utcTime)
{
//	MmsType fcdaType = MmsValue_getType(fcdaMmsValue);
//	switch(fcdaType)
//	{
//	case MMS_ARRAY:
//	case MMS_STRUCTURE:
//		fcdaMmsValue = MmsValue_getElement(fcdaMmsValue,0);
//		break;
//	default:
//		break;
//	}
//
//	char strFcdaMmsValue[64] = {0};
//	MmsValue_printToBuffer(fcdaMmsValue, strFcdaMmsValue, 64);
//
//	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, fcda + " type:" + MmsValue_getTypeString(fcdaMmsValue) +
//																		string("  value:") + strFcdaMmsValue +
//																		" utcTime:" + utcTime);
//
//	PointValueType ctype = getPointValueType(fcdaMmsValue);
//
//	RtdbMessage rtdbMessage;
//	rtdbMessage.set_messagetype(TYPE_REALPOINT);
//
//	RealPointValue* realPointValue = rtdbMessage.mutable_realpointvalue();
//	realPointValue->set_channelname(SingletonConfig->getChannelName());
//	realPointValue->set_pointvalue(strFcdaMmsValue);
//	realPointValue->set_pointaddr(redisAddr);
//	realPointValue->set_valuetype(ctype);
//	realPointValue->set_channeltype(2);                                       //通道类型，1-采集  2-网分
//	realPointValue->set_timevalue(utcTime);                                        //实时点时标
//	realPointValue->set_sourip(mmsContent.srcIp);
//	realPointValue->set_destip(mmsContent.dstIp);
//	realPointValue->set_protocoltype("IEC61850");
//	//realPointValue->set_pcapfilename(mmsContent.pcapFile);
//
//	string dataBuf;
//	rtdbMessage.SerializeToString(&dataBuf);
//
//	return redisHelper->publish(REDIS_CHANNEL_CONFIG, dataBuf, string("6014_") + SingletonConfig->getPubAddrByFcda(fcda) + "_2");
	return 0;
}

void PacketParse::run()
{
	while(isRunning)
	{
		stGooseContent gooseContent;
		if(queGooseContent.pop_front(gooseContent))
		{
			analysisGooseContent(gooseContent);
		}
	}
}

void PacketParse::subscribe()
{
	redisHelper = new RedisHelper(SingletonConfig->getRedisIp() + ":" + boost::lexical_cast<string>(SingletonConfig->getRedisPort()));   //取消自动重连，因为自动重连，需要重新订阅,但是无法获知何时重连成功
	while(isRunning)
	{
		if(!redisHelper->check_connect())
		{
			if(redisHelper->open())
			{
				SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "Redis Connect Success:" + SingletonConfig->getRedisIp());
				if(redisHelper->subscribe(SingletonConfig->getChannelName()) >= 1)
				{
					SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "Redis Subscribe Success:" + SingletonConfig->getChannelName());
				}
			}
			else
			{
				SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_WARN, "Redis Connect Failure:" + SingletonConfig->getRedisIp());
				sleep(1);
				continue;
			}
		}

		string message;
		if(redisHelper->getMessage(message))
		{
			RtdbMessage rtdbMessage;
			if(rtdbMessage.ParseFromString(message))
			{
				//RemoteControl remoteControl = rtdbMessage.remotecontrol();
				//LOG_DEBUG(remoteControl.protocolname());

				switch(rtdbMessage.messagetype())
				{
				case TYPE_REALPOINT:
				{
					RealPointValue realPointValue = rtdbMessage.realpointvalue();
					SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, realPointValue.pointaddr() + " " + realPointValue.pointvalue());
					break;
				}
				case TYPE_HEARTBEATMESSAGE:
				{
					HeartBeatMessage heartBeatMessage = rtdbMessage.heartbeatmessage();
					SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "heartTime:" + boost::lexical_cast<string>(heartBeatMessage.time()));
					break;
				}
				case TYPE_LOGREQUEST:
				{
					LogRequest logRequest = rtdbMessage.logrequest();
					SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "channel:" + logRequest.channelname() + " command:" + boost::lexical_cast<string>(logRequest.command()));
					if(logRequest.channelname().compare(SingletonConfig->getChannelName()) == 0)
					{
						SingletonLog4cplus->setLogRequestFlag(logRequest.command());
					}
					break;
				}
				default:
					break;
				}
			}
			else
			{
				SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_WARN, "ParseFromString Failure");
			}
		}
	}
}

void PacketParse::sendHeartBeat()         //发送心跳
{
	heatRedisHelper = new RedisHelper(SingletonConfig->getRedisIp() + ":" + boost::lexical_cast<string>(SingletonConfig->getRedisPort()), true);  //设置自动重连
	heatRedisHelper->open();
	while(isRunning)
	{
		sleep(10);
		RtdbMessage rtdbMessage;
		rtdbMessage.set_messagetype(TYPE_HEARTBEATMESSAGE);

		HeartBeatMessage* heartBeatMessage = rtdbMessage.mutable_heartbeatmessage();
		heartBeatMessage->set_time(time(NULL));
		heartBeatMessage->set_channelname(SingletonConfig->getChannelName());

		string message;
		rtdbMessage.SerializeToString(&message);

		heatRedisHelper->publish(REDIS_CHANNEL_CONFIG, message);
		SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "Write Heart Beat");
	}
}

void PacketParse::start()
{
	boost::function0< void> runFun =  boost::bind(&PacketParse::run,this);
	boost::thread runThread(runFun);
	runThread.detach();

	boost::function0< void> subscribeFun =  boost::bind(&PacketParse::subscribe,this);
	boost::thread redisThread(subscribeFun);
	redisThread.detach();

	boost::function0< void> sendHeartBeatFun =  boost::bind(&PacketParse::sendHeartBeat,this);
	boost::thread sendHeartBeatThread(sendHeartBeatFun);
	sendHeartBeatThread.detach();
}

void PacketParse::stop()
{
	isRunning = false;
}

