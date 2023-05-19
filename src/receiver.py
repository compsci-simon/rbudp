import json
import socket
import pickle
import threading
import sys
from PyQt6.QtWidgets import (
    QApplication,
    QWidget, 
    QLabel, 
    QPushButton, 
    QLineEdit, 
    QVBoxLayout, 
    QProgressBar,
    QFileDialog,
    QHBoxLayout,
    QStackedLayout,
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt

import Constants

class Worker(QThread):
    # Create a custom signal to communicate with the main thread
    progress_update = pyqtSignal(int)
    update_header = pyqtSignal(str)

    def __init__(self, ip, tcp, udp, filename):
        super().__init__()

        self.ip = ip
        self.tcp = tcp
        self.udp = udp
        self.filename = filename

    def run(self):
        receiver = Receiver(self.ip, int(self.tcp), int(self.udp), self.filename)
        receiver.accept_connection(self.update_header.emit, self.progress_update.emit)
        

class ReceiverGUI(QWidget):

    def __init__(self):
        super().__init__()

        self.setFixedSize(500, 350)
        self.setWindowTitle('Server')
        self.createHomescreen()
        self.createReceivescreen()
        self.qlayout = QStackedLayout(self)
        self.qlayout.addWidget(self.homescreen)
        self.qlayout.addWidget(self.receiveScreen)
        self.setLayout(self.qlayout)
        self.qlayout.setCurrentIndex(0)
        self.show()

    def createHomescreen(self):

        components = [[None, None] for _ in range(7)]
        self.homescreen = QWidget(self)
        layout = QVBoxLayout(self.homescreen)
        layout.setContentsMargins(100, 50, 100, 50)
        self.homescreen.setLayout(layout)

        self.ip_textbox = QLineEdit(self.homescreen)
        self.tcp_port_textbox = QLineEdit(self.homescreen)
        self.udp_port_textbox = QLineEdit(self.homescreen)
        self.output_dir_label = QLabel('No output dir', self.homescreen)
        select_dir = QPushButton('Select output directory')
        button = QPushButton('Start receiver', self.homescreen)
        self.error_text = QLabel('')

        components[0][0] = QLabel('IP:')
        components[0][1] = self.ip_textbox
        components[1][0] = QLabel('TCP Port:')
        components[1][1] = self.tcp_port_textbox
        components[2][0] = QLabel('UDP Port:')
        components[2][1] = self.udp_port_textbox
        components[3][0] = QLabel('Output directory:')
        components[3][1] = self.output_dir_label
        components[4][0] = select_dir
        components[5][1] = button
        components[6][1] = self.error_text


        for row in components:
            hbox = QHBoxLayout()
            hbox.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            for component in row:
                if component is not None:
                    hbox.addWidget(component)
            layout.addLayout(hbox)

        select_dir.clicked.connect(self.getdir)
        button.clicked.connect(self.receive_connections)
        
    def createReceivescreen(self):
        self.receiveScreen = QWidget(self)
        layout = QVBoxLayout()

        components = [[None, None] for _ in range(2)]
        
        self.receive_screen_header = QLabel('Waiting to start receiving file from client...', self.receiveScreen)
        self.progressBar = QProgressBar(self)

        components[0][0] = self.receive_screen_header
        components[1][0] = self.progressBar

        for row in components:
            hbox = QHBoxLayout()
            hbox.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            for component in row:
                if component is not None:
                    hbox.addWidget(component)
            layout.addLayout(hbox)

        self.receiveScreen.setLayout(layout)

    def getdir(self):
        self.fname = QFileDialog.getExistingDirectory(self, 'Open file', '~/')
        print(self.fname)
        self.output_dir_label.setText(self.fname)

    def receive_connections(self):
        ip = self.ip_textbox.text()
        tcp_port = self.tcp_port_textbox.text()
        udp_port = self.udp_port_textbox.text()
        out_dir = self.output_dir_label.text()

        ip = 'localhost'
        tcp_port = '1234'
        udp_port = '12345'
        out_dir = '/Users/simon/Desktop/'

        if not ip or not tcp_port or not udp_port or not out_dir:
            self.error_text.setText("All fields are required.")
            return

        self.worker = Worker(ip, tcp_port, udp_port, out_dir)
        self.worker.progress_update.connect(self.updateProgressBar)
        self.worker.update_header.connect(self.updateHeader)
        self.worker.start()

        print(f'ip = {ip}, tcp_port = {tcp_port}, udp_port = {udp_port}, out_dir = {out_dir}')
        self.qlayout.setCurrentIndex(1)

    def updateHeader(self, text):
        self.receive_screen_header.setText(text)

    def updateProgressBar(self, value):
        self.progressBar.setValue(value)


class Receiver:

    def __init__(self, ip, tcp_port, udp_port, out_dir):
        self.tcp_sock = None
        self.udp_sock = None
        self.ip = ip
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.out_dir = out_dir
        self.udp_timeout = 0.01

    def accept_connection(self, update_header_func=None, set_progress_bar=None):
        print('Waiting for TCP connection')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_sock:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
                # We set socket options to allow this address to be reused.
                # This prevent an errno [48] error if you try to run the server too
                # quickly after it has shut down and the operating system has reclaimed
                # this socket address and port
                tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.tcp_sock = tcp_sock
                self.udp_sock = udp_sock
                self.tcp_sock.bind((self.ip, self.tcp_port))
                self.udp_sock.bind((self.ip, self.udp_port))
                self.set_progress_bar = set_progress_bar
                self.tcp_sock.listen()

                while True:
                    try:
                        self.sender, _ = self.tcp_sock.accept()
                        if update_header_func is not None:
                            update_header_func('Client has connected')
                        self.accept_messages()
                    except Exception as e:
                        if update_header_func is not None:
                            update_header_func('Client has disconnected')
                        if set_progress_bar is not None:
                            set_progress_bar(0)
                        import traceback
                        traceback.print_exc()
                        continue

    def udp_recv(self):
        header = self.udp_sock.recv(Constants.HEADER_SIZE, socket.MSG_PEEK).decode('utf8')
        msg_len = int(header)
        payload_bytes = self.udp_sock.recv(Constants.HEADER_SIZE + msg_len)[Constants.HEADER_SIZE:]
        return pickle.loads(payload_bytes)
    
    def tcp_recv(self):
        header_text = self.sender.recv(Constants.HEADER_SIZE).decode('utf8')
        if header_text == '':
            raise Exception('Client disconnected')
        msg_len = int(header_text)
        msg = json.loads(self.sender.recv(msg_len).decode('utf8'))
        return msg

    def tcp_send(self, message):
        try:
            encoded_msg = json.dumps(message).encode('utf8')
            header = f'{len(encoded_msg)}'.ljust(Constants.HEADER_SIZE).encode('utf8')
            self.sender.send(header+encoded_msg)
        except Exception as e:
            print(f'Message cannot be encode: {e}')
        pass

    def accept_messages(self):
        while True:
            print('Waiting for message')
            msg = self.tcp_recv()
            if 'code' not in msg:
                print(f'message without code field is not recognized.')
                continue
            if msg['code'] == Constants.START_RBUDP_TRANSFER:
                self.rbudp_recv(msg)
            elif msg['code'] == Constants.START_TCP_TRANSFER:
                self.tcp_file_recv(msg)
            elif msg['code'] == Constants.PING:
                self.tcp_send({ 'code': Constants.MESSAGE_OK })
            else:
                print(f'Unrecognized message code: {msg["code"]}')
                continue
    
    def rbudp_recv(self, msg):
        self.udp_sock.settimeout(2)
        while True:
            try:
                chunk = self.udp_recv()
                print(f'LATE CHUNK: {chunk["id"]}')
            except socket.error:
                print('Done receiving late chunks.')
                break
        self.udp_sock.settimeout(self.udp_timeout)
        if self.set_progress_bar:
            self.set_progress_bar(0)
        if 'code' not in msg:
            raise Exception(f'Incorrect message format: {msg}')
        if msg['code'] != Constants.START_RBUDP_TRANSFER:
            raise Exception('Non rbudp start code received.')
        if 'metadata' not in msg:
            raise Exception('"metadata" not in message')
        metadata = msg['metadata']
        transfer_id = metadata['transfer_id']
        blastsize = metadata['blastsize']
        chunks = {}
        total_chunks = metadata['total_chunks']
        filename = metadata['filename']
        self.tcp_send({ 'code': Constants.MESSAGE_OK })
        while len(chunks.keys()) < total_chunks:
            self.recv_blast(chunks, total_chunks, blastsize, transfer_id)
        
        file_bytes = b''
        for i in range(total_chunks):
            file_bytes += chunks[i]['payload']
        print(f'len(file_bytes)={len(file_bytes)}')
        with open(self.out_dir+filename, 'wb') as f:
            f.write(file_bytes)
            
    def recv_blast(self, chunks, total_chunks, blastsize, transfer_id):
        chunks_to_receive = total_chunks - len(chunks.keys())
        lock = threading.Lock()
        def attempt_to_recv_udp_packet(receiver, chunks, lock, transfer_id):
            try:
                chunk = receiver.udp_recv()
                if chunk['transfer_id'] != transfer_id:
                    raise Exception(f'chunk with id {chunk["id"]} has invalid transfer_id')
                print(f'received chunk {chunk["id"]}')
                lock.acquire()
                chunk['sender_knows_have_received'] = False
                chunks[chunk['id']] = chunk
                lock.release()
            except:
                pass

        for _ in range(0, min(chunks_to_receive, blastsize)):
            thread = threading.Thread(target=attempt_to_recv_udp_packet, args=(self, chunks, lock, transfer_id))
            thread.start()
        msg = self.tcp_recv()
        if msg['code'] != Constants.BLAST_END:
            raise Exception(f'Expect blast end signal, but found {msg}')
        # signal every key that has ever been received.
        lock.acquire()
        received = []
        for chunk in chunks.values():
            if not chunk['sender_knows_have_received']:
                chunk['sender_knows_have_received'] = True
                received.append(chunk['id'])
        self.tcp_send(list(chunks.keys()))
        lock.release()

        progress = len(chunks.keys()) / total_chunks
        if self.set_progress_bar:
            self.set_progress_bar(int(100*progress))

    def tcp_file_recv(self, msg):
        file_bytes = b''
        i = 0
        metadata = msg['metadata']
        print(f'msg = {msg}')
        filesize = metadata['filesize']
        print(f'filesize = {filesize}')
        import math
        while True:
            chunk = self.sender.recv(Constants.CHUNKS_SIZE)
            progress = math.ceil(100*len(file_bytes)/filesize)
            if self.set_progress_bar:
                self.set_progress_bar(progress)
            if not chunk:
                break
            else:
                print(f'received chunks {i*1024}:{(i+1)*1024}')
                file_bytes += chunk
                if len(file_bytes) == filesize:
                    break
            i += 1
        filename = msg['metadata']['filename']
        with open(self.out_dir+filename, 'wb') as f:
            f.write(file_bytes)


if __name__ == '__main__':
    # receiver = Receiver(output_filename='book2.pdf')
    # receiver.accept_connection()
    # receiver.rbudp_recv()
    app = QApplication(sys.argv)
    ex = ReceiverGUI()
    sys.exit(app.exec())
    