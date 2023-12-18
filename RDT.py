import Network
import argparse
import time
from time import sleep
import hashlib
import math

# Constants
debug = False
packet_len = 10
window_size = 4
# default = False


def debug_log(message):
    if debug:
        print(message)


class Packet:
    # the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    # length of md5 checksum in hex
    checksum_length = 32
    

    def __init__(self, seq_num, msg_S, last=False):
        self.seq_num = seq_num
        self.msg_S = msg_S
        self.last = last

    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt {}'.format(byte_S))

        # extract the fields
        last = bool(int(byte_S[0]))
        seq_num = int(byte_S[1 + Packet.length_S_length:1 + Packet.length_S_length + Packet.seq_num_S_length])
        msg_S = byte_S[1 + Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length:]
        return self(seq_num, msg_S, last)

    def get_byte_S(self):
        # convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        # convert length to a byte field of length_S_length bytes
        length_S = str(1 + self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(
            self.length_S_length)
        # Last as a byte
        last = '1' if self.last else '0'
        # compute the checks0um
        checksum = hashlib.md5((last + length_S + seq_num_S + self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        # compile into a string
        return last + length_S + seq_num_S + checksum_S + self.msg_S

    @staticmethod
    def corrupt(byte_S):
        # extract the fields
        last = byte_S[0]
        length_S = byte_S[1:(Packet.length_S_length + 1)]
        seq_num_S = byte_S[(Packet.length_S_length + 1): (Packet.length_S_length + Packet.seq_num_S_length + 1)]
        length = int(length_S)
        checksum_S = byte_S[
                     (1 + Packet.seq_num_S_length + Packet.seq_num_S_length): (1 + Packet.seq_num_S_length + Packet.length_S_length + Packet.checksum_length)]
        msg_S = byte_S[(1 + Packet.seq_num_S_length + Packet.seq_num_S_length + Packet.checksum_length):length]

        # compute the checksum locally
        checksum = hashlib.md5(str(last + length_S + seq_num_S + msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        # and check if the same
        return checksum_S != computed_checksum_S

    def is_ack_pack(self):
        if self.msg_S == '1' or self.msg_S == '0':
            return True
        return False


class RDT:
    # latest sequence number used in a packet
    seq_num = 0
    # buffer of bytes read from network
    byte_buffer = ''
    timeout = 0.1
    return_value = ''
    pkt_buf = []
    msg_total = 0
    bytes_total = 0
    pkts_total = 0
    re_pkts_total = 0
    re_pkts_msg = 0
    re_pkts_ack = 0
    corr_pkts_total = 0
    corr_pkts_msg = 0
    corr_pkts_ack = 0
    corr_pkts_rec = 0

    def __init__(self, role_S, server_S, port):
        self.network = Network.NetworkLayer(role_S, server_S, port)
        self.time = time.time()

    def rdt_4_0_send(self, msg: str):
        pkts = self._break_message(msg)
        window = [(pkts[i], 0) for i in range(0, window_size)]
        i = window_size
        while len(window) > 0:
            for j in range(0, len(window)):
                if window[j][1] == 0:
                    t = time.time()
                    self.network.udt_send(window[j][0].get_byte_S())
                    window[j] = (window[j][0], t)
                    debug_log("Sent pkt {} {}".format(window[j][0].seq_num, window[j][0].get_byte_S()))
                    self.pkts_total += 1
                    self.msg_total += len(window[j][0].msg_S)
                    self.bytes_total += len(window[j][0].get_byte_S())

            while len(self.byte_buffer) < (1 + Packet.length_S_length):
                self.byte_buffer += self.network.udt_receive()
                for j in range(0, len(window)):
                    if (window[j][1] + self.timeout) < time.time():
                        t = time.time()
                        self.network.udt_send(window[j][0].get_byte_S())
                        window[j] = (window[j][0], t)
                        self.pkts_total += 1
                        self.re_pkts_total += 1
                        self.re_pkts_msg += 1
                        self.bytes_total += len(window[j][0].get_byte_S())

            #debug_log("SENDER: " + response)

            try:
                msg_length = int(self.byte_buffer[1:Packet.length_S_length + 1])
                
                if Packet.corrupt(self.byte_buffer[:msg_length]):
                    self.byte_buffer = self.byte_buffer[msg_length:]
                    self.corr_pkts_total += 1
                    self.corr_pkts_rec += 1
                    continue
                else:
                    res_p = Packet.from_byte_S(self.byte_buffer[:msg_length])
                    self.byte_buffer = self.byte_buffer[msg_length:]
                    seq_nums = [pkt[0].seq_num for pkt in window]
                    try:
                        ind = seq_nums.index(res_p.seq_num)
                        # recieved NACK
                        if res_p.msg_S == "0":
                            t = time.time()
                            self.corr_pkts_total += 1
                            self.corr_pkts_msg += 1
                            self.pkts_total += 1
                            self.re_pkts_total += 1
                            self.re_pkts_msg += 1
                            self.bytes_total += len(window[j][0].get_byte_S())
                            self.network.udt_send(window[ind][0].get_byte_S())
                            window[j] = (window[ind][0], t)
                        # recieved ACK
                        elif res_p.msg_S == "1":
                            debug_log("SENDER: Received ACK {}, move on to next.".format(res_p.seq_num))
                            window.pop(ind)
                            if i < len(pkts):
                                window.append((pkts[i], 0))
                                i += 1
                            debug_log(f"Window: {[pkt[0].seq_num for pkt in window]}")
                            continue
                    except:
                        # It's trying to send me data again
                        if self.seq_num > res_p.seq_num:
                            debug_log("SENDER: Receiver behind sender")
                            answer = Packet(res_p.seq_num, "1")
                            self.pkts_total += 1
                            self.bytes_total += len(answer.get_byte_S())
                            self.re_pkts_total += 1
                            self.re_pkts_ack += 1
                            self.network.udt_send(answer.get_byte_S())
                            debug_log("ACK sent: {}".format(answer.get_byte_S()))
            except:
                self.byte_buffer = ''
                self.corr_pkts_total += 1
                self.corr_pkts_rec += 1
                continue
        debug_log(f"SENDER: done, beg seq_num: {self.seq_num}, end seq_num: {self.seq_num + len(pkts)}")
        self.seq_num += len(pkts)
                    
    
    def rdt_4_0_receive(self):
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        ret_S = None
        while True:
            # check if we have received enough bytes
            if len(self.byte_buffer) < Packet.length_S_length + 1:
                break  # not enough bytes to read packet length
            # extract length of packet
            try:
                length = int(self.byte_buffer[1:Packet.length_S_length + 1])
            except:
                self.byte_buffer = ''
                debug_log("RECEIVER: Corrupt packet, sending NAK.")
                self.pkts_total += 1
                self.corr_pkts_total += 1
                self.corr_pkts_rec += 1
                answer = Packet(self.seq_num, "0")
                self.bytes_total += len(len(answer.get_byte_S()))
                self.network.udt_send(answer.get_byte_S())
                continue
            if len(self.byte_buffer) < length:
                break  # not enough bytes to read the whole packet

            debug_log(f"Recieving: {self.byte_buffer}")

            # Check if packet is corrupt
            if Packet.corrupt(self.byte_buffer[0:length]):
                # Send a NAK
                self.byte_buffer = self.byte_buffer[length:]
                debug_log("RECEIVER: Corrupt packet, sending NAK.")
                answer = Packet(self.seq_num, "0")
                self.pkts_total += 1
                self.corr_pkts_total += 1
                self.corr_pkts_rec += 1
                self.bytes_total += len(len(answer.get_byte_S()))
                self.network.udt_send(answer.get_byte_S())
            else:
                # create packet from buffer content
                p = Packet.from_byte_S(self.byte_buffer[0:length])
                # Check packet
                if p.is_ack_pack():
                    debug_log('is ACK/NACK pkt')
                    self.byte_buffer = self.byte_buffer[length:]
                    continue
                if p.seq_num == self.seq_num:
                    debug_log('RECEIVER: Received new.  Send ACK and increment seq.')
                    # SEND ACK
                    answer = Packet(self.seq_num, "1")
                    self.pkts_total += 1
                    self.bytes_total += len(answer.get_byte_S())
                    self.network.udt_send(answer.get_byte_S())
                    debug_log("RECEIVER: Incrementing seq_num from {} to {}".format(self.seq_num, self.seq_num + 1))
                    debug_log("ACK sent: {}".format(answer.get_byte_S()))
                    self.byte_buffer = self.byte_buffer[length:]
                    self.seq_num += 1
                    self.return_value += p.msg_S
                    if self.pkt_buf:
                        while self.pkt_buf and (self.pkt_buf[0][0] == self.seq_num):
                            self.return_value += self.pkt_buf[0][1]
                            self.seq_num += 1
                            debug_log("RECEIVER: Incrementing seq_num from {} to {}".format(self.seq_num, self.seq_num + 1))
                            last = self.pkt_buf.pop(0)
                            if last[2] == True:
                                curr = self.return_value
                                self.return_value = ''
                                return curr
                    if p.last == True:
                        self.pkt_buf = []
                        curr = self.return_value
                        self.return_value = ''
                        return curr
                elif p.seq_num > self.seq_num:
                    answer = Packet(p.seq_num, "1")
                    self.pkts_total += 1
                    self.bytes_total += len(answer.get_byte_S())
                    self.msg_total += 1
                    self.network.udt_send(answer.get_byte_S())
                    debug_log("ACK sent: {}".format(answer.get_byte_S()))
                    self.byte_buffer = self.byte_buffer[length:]
                    seq_nums = [pkt[0] for pkt in self.pkt_buf]
                    if not p.seq_num in seq_nums:
                        self.pkt_buf.append((p.seq_num, p.msg_S, p.last))
                        self.pkt_buf.sort(key=lambda x: x[0])
                        debug_log(f"PKT out of order, pkt_buf: {self.pkt_buf}")
                    while self.pkt_buf and (self.pkt_buf[0][0] == self.seq_num):
                            self.return_value += self.pkt_buf[0][1]
                            self.seq_num += 1
                            debug_log("RECEIVER: Incrementing seq_num from {} to {}".format(self.seq_num, self.seq_num + 1))
                            last = self.pkt_buf.pop(0)
                            if last[2] == True:
                                curr = self.return_value
                                self.return_value = ''
                                return curr
                else:
                    # seq_num < self.seq_num
                    debug_log("SENDER BEHIND RECIEVER")
                    answer = Packet(p.seq_num, "1")
                    self.pkts_total += 1
                    self.bytes_total += len(answer.get_byte_S())
                    self.re_pkts_total += 1
                    self.re_pkts_ack += 1
                    self.network.udt_send(answer.get_byte_S())
                    debug_log("ACK sent: {}".format(answer.get_byte_S()))
                    self.byte_buffer = self.byte_buffer[length:]
        return ret_S


    def disconnect(self):
        self.network.disconnect()

    def rdt_3_0_send(self, msg_S):
        p = Packet(self.seq_num, msg_S)
        current_seq = self.seq_num

        while current_seq == self.seq_num:
            self.network.udt_send(p.get_byte_S())
            response = ''
            timer = time.time()

            # Waiting for ack/nak
            while response == '' and timer + self.timeout > time.time():
                response = self.network.udt_receive()

            if response == '':
                continue

            debug_log("SENDER: " + response)

            msg_length = int(response[:Packet.length_S_length])
            self.byte_buffer = response[msg_length:]

            if not Packet.corrupt(response[:msg_length]):
                response_p = Packet.from_byte_S(response[:msg_length])
                if response_p.seq_num < self.seq_num:
                    # It's trying to send me data again
                    debug_log("SENDER: Receiver behind sender")
                    test = Packet(response_p.seq_num, "1")
                    self.network.udt_send(test.get_byte_S())
                elif response_p.msg_S is "1":
                    debug_log("SENDER: Received ACK, move on to next.")
                    debug_log("SENDER: Incrementing seq_num from {} to {}".format(self.seq_num, self.seq_num + 1))
                    self.seq_num += 1
                elif response_p.msg_S is "0":
                    debug_log("SENDER: NAK received")
                    self.byte_buffer = ''
            else:
                debug_log("SENDER: Corrupted ACK")
                self.byte_buffer = ''

    def rdt_3_0_receive(self):
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        current_seq = self.seq_num
        # Don't move on until seq_num has been toggled
        # keep extracting packets - if reordered, could get more than one
        while current_seq == self.seq_num:
            # check if we have received enough bytes
            if len(self.byte_buffer) < Packet.length_S_length:
                break  # not enough bytes to read packet length
            # extract length of packet
            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                break  # not enough bytes to read the whole packet

            # Check if packet is corrupt
            if Packet.corrupt(self.byte_buffer):
                # Send a NAK
                debug_log("RECEIVER: Corrupt packet, sending NAK.")
                answer = Packet(self.seq_num, "0")
                self.network.udt_send(answer.get_byte_S())
            else:
                # create packet from buffer content
                p = Packet.from_byte_S(self.byte_buffer[0:length])
                # Check packet
                if p.is_ack_pack():
                    self.byte_buffer = self.byte_buffer[length:]
                    continue
                if p.seq_num < self.seq_num:
                    debug_log('RECEIVER: Already received packet.  ACK again.')
                    # Send another ACK
                    answer = Packet(p.seq_num, "1")
                    self.network.udt_send(answer.get_byte_S())
                elif p.seq_num == self.seq_num:
                    debug_log('RECEIVER: Received new.  Send ACK and increment seq.')
                    # SEND ACK
                    answer = Packet(self.seq_num, "1")
                    self.network.udt_send(answer.get_byte_S())
                    debug_log("RECEIVER: Incrementing seq_num from {} to {}".format(self.seq_num, self.seq_num + 1))
                    self.seq_num += 1
                # Add contents to return string
                ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
            # remove the packet bytes from the buffer
            self.byte_buffer = self.byte_buffer[length:]
            # if this was the last packet, will return on the next iteration
        return ret_S

    def _break_message(self, message: str):
        num_pkt = int(math.ceil(float(len(message))/packet_len))
        pkts = []
        for i in range(0, num_pkt - 1):
            pkts.append(Packet(self.seq_num + i, message[i * packet_len:(i + 1) * packet_len]))
        i += 1
        pkts.append(Packet(self.seq_num + i, message[i * packet_len:(i + 1) * packet_len], True))
        return pkts
    
    def stats(self):
        res = {}
        res["goodput"] = self.msg_total / (time.time() - self.time)
        res["vazao"] = self.bytes_total / (time.time() - self.time)
        res["Total de Pacotes"] = self.pkts_total
        res["Total de Retransmissões"] = self.re_pkts_total
        res["Retransmissões de ACK/NACK"] = self.re_pkts_ack
        res["Retransmissões de mensagens"] = self.re_pkts_msg
        res["Total de Pacotes Corrompidos"] = self.corr_pkts_total
        res["Pacotes ACK Corrompidos"] = self.corr_pkts_ack
        res["Pacotes de mensagem Corrompidos"] = self.corr_pkts_msg
        res["Pacotes recebidos Corrompidos"] = self.corr_pkts_rec
        res["Tempo de simulacao"] = time.time() - self.time
        return res


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_3_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_3_0_receive())
        rdt.disconnect()


    else:
        sleep(1)
        print(rdt.rdt_3_0_receive())
        rdt.rdt_3_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
