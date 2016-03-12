#ifndef PROTOCOL_H_
#define PROTOCOL_H_

#define		NET_PACKET_MAX			128

#define		NET_OK					0x00
#define		NET_ERROR				0x01

#define		NET_CL_REQ_PUBLIC		0x10
#define		NET_CL_REQ_SECRET		0x11
#define		NET_CL_REQ_STATUS		0x12
#define		NET_CL_RELEASE			0x13

#define		NET_SV_PUBLIC			0x20
#define		NET_SV_SECRET			0x21
#define		NET_SV_TOKEN_REUSED		0x22

#define		NET_CTL_SHUTDOWN		0x30

#endif
