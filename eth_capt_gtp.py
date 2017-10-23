#!/usr/bin/env python
# _*_ coding: utf-8 _*_
import pcap, dpkt  #或者pcap-python3
import sys, socket, json, re, zlib
from time import strftime, localtime, time
from collections import defaultdict

# 反复使用的方法变量对象绑定
socket__inet_ntoa = socket.inet_ntoa
dpkt__ethernet__Ethernet = dpkt.ethernet.Ethernet
dpkt__http__Request = dpkt.http.Request
dpkt__http__Response = dpkt.http.Response
json__dump = json.dump
PktHdr__hdr_len = dpkt.pcap.PktHdr.__hdr_len__
# zip_decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress

request_methods = (
            'GET', 'PUT', 'ICY',
            'COPY', 'HEAD', 'LOCK', 'MOVE', 'POLL', 'POST',
            'BCOPY', 'BMOVE', 'MKCOL', 'TRACE', 'LABEL', 'MERGE',
            'DELETE', 'SEARCH', 'UNLOCK', 'REPORT', 'UPDATE', 'NOTIFY',
            'BDELETE', 'CONNECT', 'OPTIONS', 'CHECKIN',
            'PROPFIND', 'CHECKOUT', 'CCM_POST',
            'SUBSCRIBE', 'PROPPATCH', 'BPROPFIND',
            'BPROPPATCH', 'UNCHECKOUT', 'MKACTIVITY',
            'MKWORKSPACE', 'UNSUBSCRIBE', 'RPC_CONNECT',
            'VERSION-CONTROL',
            'BASELINE-CONTROL')
http_request_compile = re.compile("".join(["(", "|".join(request_methods), ")",
                                        "\s+/[^\s]+", "(\s+HTTP[^\s]*)*", "\s*[\r\n]+"]))
http_response_compile = re.compile(r"HTTP[^\s]*\s+\d+\s+[^\r\n]*\s*[\r\n]+")


class GtpRepackaged(object):
    """gtp数据封装类,数据格式参考http://www.cnblogs.com/lvdongjie/p/4064574.html
    """
    def __init__(self, snaplen=1500, linktype=dpkt.pcap.DLT_EN10MB, nano=False):
        self._precision = 9 if nano else 6

    def get_gtppkt(self, pkt, ts=None):
        """ph: Packet包头
           s:  Packet数据
        """
        if ts is None: ts = time()
        s = bytes(pkt)

        n = len(s)
        sec = int(ts)
        usec = int(round(ts % 1 * 10 ** self._precision))

        if sys.byteorder == 'little':
            ph = dpkt.pcap.LEPktHdr(tv_sec=sec,
                          tv_usec=usec,
                          caplen=n, len=n)
        else:
            ph = dpkt.pcap.PktHdr(tv_sec=sec,
                        tv_usec=usec,
                        caplen=n, len=n)

        return bytes(ph) + s


class CaptData(object):
    def __init__(self, capt_name=None, filter_rule=None, result_file="./http_info.json"):
        """capt_name 可以是离线数据包*.pcap，可以是网卡名(如"eth0")，还可是None(表示捕获所有数据)
        """
        # 创建pkt封装方法对象， 结果存储文件(默认json), 层次数据包统计dict
        self.gtp_data, json_fout, self.level_num_dict = GtpRepackaged().get_gtppkt, open(result_file, 'w'), defaultdict(int)

        trace_format = """
        Origin_pkt:       %(Origin_pkt)15d
        IP:               %(IP_pkt)15d
        UDP:              %(UDP_pkt)15d
        GTP:              %(GTP_pkt)15d
        GTP/IP:           %(GTP_IP_pkt)15d
        IP/TCP:           %(GTP_TCP_pkt)15d
        TCP/nodata:       %(GTP_no_intcp_pkt)15d
        Request/true:     %(GTP_HTTP_trueREQUEST_pkt)15d
        Request/err:      %(GTP_HTTP_errREQUEST_pkt)15d
        Response/true:    %(GTP_HTTP_trueRESPONSE_pkt)15d
        Response/err:     %(GTP_HTTP_errRESPONSE_pkt)15d
        TCP/notHttp:      %(GTP_notHTTP_pkt)15d
        """

        # 离线数据包*.pcap
        if isinstance(capt_name, str) and capt_name.endswith(".pcap"):
            fin = open(capt_name, "rb")
            pc = dpkt.pcap.Reader(fin)
        # 直接捕获网卡
        else:
            pc = pcap.pcap(name=capt_name)
            pc.setfilter(filter_rule) if filter_rule else None

        # 抓取数据并逐条解析，拆出gtp下的http协议
        try:
            for ts, buff in pc:
                if __debug__: self.level_num_dict["Origin_pkt"] += 1
                eth0 = dpkt__ethernet__Ethernet(buff)

                # 调用gtp函数，返回gtp段数据并逐条解析
                gtp_alldata = self.get_gtp_data(eth0)
                if gtp_alldata is not None:
                    eth0.data = gtp_alldata
                    buff_ = self.gtp_data(eth0, ts)[PktHdr__hdr_len:]
                    tmp_httpdata = self.get_http_data(ts, buff_)
                    if tmp_httpdata:
                        json__dump(tmp_httpdata, json_fout, ensure_ascii=False, indent=4)
        except (KeyboardInterrupt, SystemExit) as e:
            pass

        try:
            fin.close()
        except Exception as e:
            pass
        json_fout.close()
        if __debug__: print trace_format % self.level_num_dict

    def get_http_data(self, ts, pkt):
        # 返回dict形式http报文
        try:
            eth = dpkt__ethernet__Ethernet(pkt)
        except Exception as e:
            print "err in eth解包"
            return None

        # 原始IP报文
        ip_level = eth.data
        if ip_level.__class__.__name__ == "IP":
            if __debug__: self.level_num_dict["GTP_IP_pkt"] += 1
            src_ip, dst_ip = socket__inet_ntoa(ip_level.dst), socket__inet_ntoa(ip_level.dst)

            # 原始TCP报文
            tcp_level = ip_level.data
            if tcp_level.__class__.__name__ == "TCP":
                if __debug__: self.level_num_dict["GTP_TCP_pkt"] += 1
                tcp_sport, tcp_dport = tcp_level.sport, tcp_level.dport

                # 原始HTTP报文（注意：此处未加80端口限制）
                http_level = tcp_level.data
                try:
                    http_level[:2]
                except Exception as e:
                    if __debug__: self.level_num_dict["GTP_no_intcp_pkt"] += 1
                    return None

                # 查找HttpRequestInfo
                request_info = http_request_compile.search(http_level)
                if request_info:
                    http_level = http_level[request_info.start():]
                    try:
                        http = dpkt__http__Request(http_level)
                        if __debug__: self.level_num_dict["GTP_HTTP_trueREQUEST_pkt"] += 1
                    except Exception as e:
                        # if __debug__: print "err in request::", http_level, e
                        if __debug__: self.level_num_dict["GTP_HTTP_errREQUEST_pkt"] += 1
                        return None
                    method = http.method
                    version = http.version
                    headers = http.headers
                    if "host" in headers:
                        url = "".join(["http://", str(headers["host"]), http.uri])
                    body = http.body
                    time_pk = strftime('%Y-%m-%d %H:%M:%S', localtime(ts))
                    tmp = locals()
                    del tmp["ip_level"], tmp["tcp_level"], tmp["http"], tmp["eth"], tmp["pkt"], tmp['ts'], tmp["self"], tmp["request_info"]
                    return tmp

                else:
                    # 查找HttpResponseInfo
                    response_info = http_response_compile.search(http_level)
                    if response_info:
                        http_level = http_level[response_info.start():]
                        if __debug__: self.level_num_dict["GTP_HTTP_trueRESPONSE_pkt"] += 1
                        try:
                            http = dpkt__http__Response(http_level)
                        except Exception as e:
                            # if __debug__: print "err in response::", http_level, e
                            if __debug__: self.level_num_dict["GTP_HTTP_errRESPONSE_pkt"] += 1
                            return None

                        version = http.version
                        status = http.status
                        reason = http.reason
                        headers = http.headers
                        body = http.body
                        time_pk = strftime('%Y-%m-%d %H:%M:%S', localtime(ts))
                        tmp = locals()
                        del tmp["ip_level"], tmp["tcp_level"], tmp["http"], tmp["eth"], tmp["pkt"], tmp['ts'], tmp["self"], tmp["response_info"]
                        return tmp

                    else:
                        if __debug__: self.level_num_dict["GTP_notHTTP_pkt"] += 1
                        return None

        return None

    def get_gtp_data(self, eth):
        try:
            # IP层
            ip_level = eth.data
            if ip_level.__class__.__name__ == "IP":
                if __debug__: self.level_num_dict["IP_pkt"] += 1
                ip = socket__inet_ntoa(ip_level.dst)

                # 此处需要解析出来UDP层
                udp_level = ip_level.data
                if udp_level.__class__.__name__ == "UDP":
                    if __debug__: self.level_num_dict["UDP_pkt"] += 1

                    # gtp标志,获取gtp层下面数据（目前涉及2种gtp版本）
                    gtp_level = udp_level.data
                    if gtp_level[0] in ["0", "2"]: # ["0", "2"] 表示[0x30, 0x32]，
                        if __debug__: self.level_num_dict["GTP_pkt"] += 1
                        gtp_alldata = gtp_level[8:] if gtp_level[0] == "0" else gtp_level[12:]
                        return gtp_alldata
                    else:
                        pass
        except Exception as e:
            if __debug__: print(e)
            return None

        return None

if __name__ == '__main__':
    from datetime import datetime as TIME
    begin = TIME.now()
    print "begin:: ", begin
    CaptData(capt_name=r"test_info\2017071710022100001011032.pcap")
    print("runtime:: %ss." % (TIME.now() - begin).seconds)