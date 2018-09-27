/*
 * ConfigIni.cpp
 *
 *  Created on: Jul 25, 2018
 *      Author: root
 */

#include "ConfigIni.h"


ConfigIni* ConfigIni::configIni = NULL;

ConfigIni* ConfigIni::getInstance()
{
	if(configIni == NULL)
	{
		configIni = new ConfigIni();
	}
	return configIni;
}
ConfigIni::ConfigIni() {
	initConfig("/home/wgj/GooseParseDemo/GooseParse/config.ini");

	initIedDescTxt("/home/wgj/GooseParseDemo/GooseParse/ieddesc.txt");

	initPointDescTxt("/home/wgj/GooseParseDemo/GooseParse/pointdesc.txt");
}

ConfigIni::~ConfigIni() {
}

bool ConfigIni::initConfig(string filename)
{
	ptree properties;
	ini_parser::read_ini(filename, properties);
	basic_ptree<string, string> lvbtItems = properties.get_child("MYSQL");
	try{
		mysqlIp = lvbtItems.get<string>("ip");
		mysqlPort = lvbtItems.get<int>("port");
		dbName = lvbtItems.get<string>("dbname");
		user = lvbtItems.get<string>("user");
		passwd = lvbtItems.get<string>("passwd");
	}
	catch (std::exception& e) {
		cerr << e.what() << endl;
	}

	return true;
}

bool ConfigIni::loadConfiguration(string filename)
{
	WgjXml wgjXML;
	if(!wgjXML.LoadXml(filename.c_str()))
	{
		return false;
	}

	ProcessManag::Map_Channel mapChannel = wgjXML.GetAllChannelName();                    //获取所有通道名
	ProcessManag::Map_Channel::iterator itChannel = mapChannel.begin();
	for( ; itChannel != mapChannel.end(); itChannel++)
	{
		if(itChannel->second.compare("IEC61850") == 0)                                    //通过直采IEC61850获取点表对应的发布点
		{
			mapFcdaToPubAddr =  wgjXML.Get_Point61850(itChannel->first);
		}
	}

	wgjXML.GetRedisConnectionConfig(redisIp,redisPort);                               //获取redis信息

	NetworkParse::Map_ParseConfig mapParseConfig = wgjXML.GetParseConfigInfo(channelName);
	NetworkParse::Map_ParseConfig::iterator it = mapParseConfig.begin();
	for( ; it != mapParseConfig.end(); it++)
	{
		if(it->first.compare("src_file_path") == 0)
		{
			srcPacpFilePath = it->second;
		}else if(it->first.compare("dst_file_path") == 0)
		{
			dstPacpFilePath = it->second;
		}else if(it->first.compare("point_table_path") == 0)
		{
			datasetFilePath = it->second;
		}else if(it->first.compare("goose_count") == 0)
		{
			packetCnt = boost::lexical_cast<int>(it->second);
		}else if(it->first.compare("heart_beat_time") == 0)
		{
			heartBeatTime = boost::lexical_cast<int>(it->second);
		}else if(it->first.compare("heart_beat_inaccuracy") == 0)
		{
			heartBeatInaccuracy = boost::lexical_cast<int>(it->second);
		}else if(it->first.compare("transmit_times") == 0)
		{
			transmitTimes = boost::lexical_cast<int>(it->second);
		}else if(it->first.compare("transmit_time") == 0)
		{
			transmitTime = boost::lexical_cast<int>(it->second);
		}else if(it->first.compare("transmit_inaccuracy") == 0)
		{
			transmitInaccuracy = boost::lexical_cast<int>(it->second);
		}else if(it->first.compare("NetWorkType") == 0)
		{
			netCardType = it->second.compare("ANetwork") == 0 ? "_01_" : "_02_";
		}
	}

	return true;
}


string ConfigIni::getPubAddrByFcda(string fcda)     //通过点名获取发布点
{
	string pubAddr;
	map<string,string>::iterator it = mapFcdaToPubAddr.find(fcda);
	if(it != mapFcdaToPubAddr.end())
	{
		pubAddr = it->second;
	}
	return pubAddr;
}

bool ConfigIni::initIedDescTxt(string path)
{
	ifstream infile(path.c_str());
	if (!infile) {
		return false;
	}
	string line, key, value;
	while (getline(infile, line)) {
		size_t pos = line.find(':');
		mapIedDesc.insert( make_pair(line.substr(0, pos), line.substr(pos + 1)));
	}
	return true;
}

bool ConfigIni::initPointDescTxt(string path)
{
	ifstream infile(path.c_str());
	if (!infile) {
		return false;
	}
	string line, key, value;
	while (getline(infile, line)) {
		size_t pos = line.find(':');
		mapPointDesc.insert(make_pair(line.substr(0, pos), line.substr(pos + 1)));
	}
	return true;
}



void ConfigIni::setChannelName(string channel)
{
	channelName = channel;
}

string ConfigIni::getChannelName() const
{
	return channelName;
}

string ConfigIni::getRedisIp() const
{
	return redisIp;
}

int ConfigIni::getRedisPort() const
{
	return redisPort;
}

string ConfigIni::getMysqlIp() const
{
	return mysqlIp;
}
int ConfigIni::getMysqlPort() const
{
	return mysqlPort;
}
string ConfigIni::getMysqlDbName() const
{
	return dbName;
}
string ConfigIni::getMysqlUser() const
{
	return user;
}
string ConfigIni::getMysqlPassWd() const
{
	return passwd;
}

string ConfigIni::getNetCardType() const
{
	return netCardType;
}

int ConfigIni::getHeartBeatTime() const
{
	return heartBeatTime;
}

int ConfigIni::getHeartBeatInaccuracy() const
{
	return heartBeatInaccuracy;
}

int ConfigIni::getTransmitTimes() const
{
	return transmitTimes;
}

int ConfigIni::getTransmitTime() const
{
	return transmitTime;
}

int ConfigIni::getTransmitInaccuracy() const
{
	return transmitInaccuracy;
}


string ConfigIni::getSrcPacpFilePath() const
{
	return srcPacpFilePath;
}

string ConfigIni::getDstPacpFilePath() const
{
	return dstPacpFilePath;
}

string ConfigIni::getDatasetFilePath() const
{
	return datasetFilePath;
}
int ConfigIni::getPacketCnt() const
{
	return packetCnt;
}


//list all key/value under setting session
//	for (basic_ptree<string, string>::iterator lvitem=lvbtItems.begin();lvitem!=lvbtItems.end();lvitem++)
//	{
//		cout << (*lvitem).first.data() << "=" << (*lvitem).second.data() << endl;
//	}

//	//change key values
//	lvptProperties.put<string>("setting.key2", "new value");
//	lvptProperties.put<int>("setting.key1", ++lvnInt);
//	//update ini file
//	ini_parser::write_ini("d:\\temp\\win.ini", lvptProperties);
