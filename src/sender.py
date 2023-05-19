import json
import math
import socket
import sys
import time
import uuid
import threading
import pickle
from PyQt6.QtWidgets import (
    QApplication,
    QWidget, 
    QPushButton,
    QLineEdit,
    QStackedLayout,
    QVBoxLayout,
    QLabel,
    QProgressBar,
    QFileDialog,
    QHBoxLayout
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt


import Constants

class GUIWorker(QThread):
    # Create a custom signal to communicate with the main thread
    progress_update = pyqtSignal(int)
    connected = pyqtSignal()
    ping_update_ui = pyqtSignal(str)

    def __init__(self, ip, tcp, udp):
        super().__init__()
        self.ip = ip
        self.tcp = tcp
        self.udp = udp

    def ping(self):
        threading.Thread(target=self.sender.ping_server, args=(self.ping_update_ui.emit,)).start()

    def tcp_send(self):
        threading.Thread(target=self.sender.tcp_file_send).start()

    def read_file(self, filename):
        threading.Thread(target=self.sender.read_file, args=(filename,)).start()

    def rbudp_send(self, chunksize=1000, blastsize=500):
        threading.Thread(target=self.sender.rbudp_send, args=(chunksize, blastsize,)).start()

    def run(self):
        self.sender = Sender(
            ip=self.ip, 
            tcp=int(self.tcp),
            udp=int(self.udp), 
            set_progress_bar=self.progress_update.emit
        )
        self.sender.connect_to_server()
        self.connected.emit()

class SenderGUI(QWidget):

    ping_signal = pyqtSignal()
    tcp_send_signal = pyqtSignal()
    rbudp_send_signal = pyqtSignal(int, int)

    def __init__(self):
        super().__init__()
        self.setFixedSize(500, 350)
        self.setWindowTitle('Client')
        self.createHomeScreen()
        self.createSendScreen()

        self.qstack = QStackedLayout(self)
        self.qstack.addWidget(self.homeWidget)
        self.qstack.addWidget(self.sendWidget)
        self.qstack.setCurrentIndex(0)
        self.show()
        
    def createHomeScreen(self):
        self.homeWidget = QWidget(self)
        layout = QVBoxLayout()
        layout.setContentsMargins(100, 80, 100, 80)

        components = [[None, None] for _ in range(5)]

        self.ip_textbox = QLineEdit(self.homeWidget)
        self.tcp_port_textbox = QLineEdit(self.homeWidget)
        self.udp_port_textbox = QLineEdit(self.homeWidget)
        button = QPushButton('Connect', self.homeWidget)
        self.error_text = QLabel('', self.homeWidget)
        
        components[0][0] = QLabel('IP:', self.homeWidget)
        components[0][1] = self.ip_textbox
        components[1][0] = QLabel('TCP Port:', self.homeWidget)
        components[1][1] = self.tcp_port_textbox
        components[2][0] = QLabel('UDP Port:', self.homeWidget)
        components[2][1] = self.udp_port_textbox
        components[3][0] = button
        components[4][0] = self.error_text


        for row in components:
            hbox = QHBoxLayout()
            hbox.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            for component in row:
                if component is not None:
                    hbox.addWidget(component)
            layout.addLayout(hbox)
        
        button.clicked.connect(self.connect)
        self.homeWidget.setLayout(layout)
   
    def createSendScreen(self):
        self.sendWidget = QWidget(self)
        layout = QVBoxLayout()

        components = [[None, None] for _ in range(9)]

        self.sendHeaderText = QLabel('Connecting to server...', self.sendWidget)
        self.filename_label = QLabel('No file yet selected', self.sendWidget)
        select_file = QPushButton('Select input file')
        packet_size_label = QLabel('Packet Size', self.sendWidget)
        self.packet_size = QLineEdit('1000', self)
        blast_size_label = QLabel('Blast Size', self.sendWidget)
        self.blast_size = QLineEdit('500', self)
        self.progressBar = QProgressBar(self.sendWidget)
        self.progress = 0
        self.progressBar.setValue(self.progress)
        self.ping_label = QLabel('Ping return time', self.sendWidget)
        ping_button = QPushButton('Ping', self.sendWidget)
        self.rbudp_error_label = QLabel('', self.sendWidget)
        rbudp_send_button = QPushButton('RBUDP send file', self.sendWidget)
        tcp_send_button = QPushButton('TCP send file', self.sendWidget)

        components[0][0] = self.sendHeaderText
        components[1][0] = self.filename_label
        components[2][0] = select_file
        components[3][0] = packet_size_label
        components[3][1] = blast_size_label
        components[4][0] = self.packet_size
        components[4][1] = self.blast_size
        components[5][0] = ping_button
        components[5][1] = self.ping_label
        components[7][0] = self.rbudp_error_label
        components[7][0] = rbudp_send_button
        components[7][1] = tcp_send_button
        components[8][0] = self.progressBar


        for row in components:
            hbox = QHBoxLayout()
            # hbox.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            for component in row:
                if component is not None:
                    hbox.addWidget(component)
            layout.addLayout(hbox)

        self.sendWidget.setLayout(layout)

        select_file.clicked.connect(self.getfile)
        ping_button.clicked.connect(self.ping_server)
        tcp_send_button.clicked.connect(self.tcp_send)
        rbudp_send_button.clicked.connect(self.rbudp_send)

    def connect(self):
        ip = self.ip_textbox.text()
        tcp_port = self.tcp_port_textbox.text()
        udp_port = self.udp_port_textbox.text()

        ip = 'localhost'
        tcp_port = '1234'
        udp_port = '12345'

        if not ip or not tcp_port or not udp_port:
            self.error_text.setText('All fields are required.')
            return

        self.worker = GUIWorker(ip, tcp_port, udp_port)
        self.worker.progress_update.connect(self.updateProgressBar)
        self.worker.connected.connect(self.update_header_text)
        self.worker.ping_update_ui.connect(self.update_ping_label)
        self.ping_signal.connect(self.worker.ping)
        self.tcp_send_signal.connect(self.worker.tcp_send)
        self.rbudp_send_signal.connect(self.worker.rbudp_send)

        self.worker.start()
        self.qstack.setCurrentIndex(1)

    def update_header_text(self):
        self.sendHeaderText.setText('Connected to server')
    
    def update_ping_label(self, text):
        self.ping_label.setText(text)

    def updateProgressBar(self, value):
        self.progressBar.setValue(value)

    def ping_server(self):
        self.ping_signal.emit()

    def tcp_send(self):
        self.tcp_send_signal.emit()

    def rbudp_send(self):
        packet_size_str = self.packet_size.text()
        blast_size_str = self.blast_size.text()
        try:
            packet_size = int(packet_size_str)
            blast_size = int(blast_size_str)
        except:
            self.rbudp_error_label.setText('Invalid parameters for packet size or blast size. Only strings accepted')
            return
        if packet_size < 1 or packet_size > 64000:
            self.rbudp_error_label.setText('Packet size should be greater than 1 and less than 64000')
        print(packet_size)
        if blast_size < 0:
            self.rbudp_error_label.setText('blast size should be greater than 0')
        self.rbudp_error_label.setText('')
        self.rbudp_send_signal.emit(packet_size, blast_size)
 
    def getfile(self):
        self.fname = QFileDialog.getOpenFileName(self, 'Open file', '~/')
        self.filename_label.setText(self.fname[0])
        print(f'{self.fname[0]}')
        self.worker.read_file(self.fname[0])

class Sender:

    def __init__(self, ip, tcp, udp, set_progress_bar):
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock = tcp_sock
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock = udp_sock
        try:
            udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            max_size = udp_sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
        except socket.error:
            max_size = 8192
        print(f'Max size of udp packets on this system are {max_size}')
        self.ip = ip
        self.tcp = tcp
        self.udp = udp
        self.set_progress_bar = set_progress_bar

    def udp_send(self, payload: dict):
        if not isinstance(payload, dict):
            raise Exception(f'Payload has to be of type dict, not type {type(payload)}')
        # We need to use pickle to serialize the dict. We cannot use json as json may not contain byte objects.
        payload_bytes = pickle.dumps(payload)
        msg_len = len(payload_bytes)
        header = f'{msg_len}'.ljust(Constants.HEADER_SIZE).encode('utf8')
        msg = header + payload_bytes
        self.udp_sock.sendto(msg, (self.ip, self.udp))

    def tcp_recv(self):
        try:
            msg_len = int(self.tcp_sock.recv(Constants.HEADER_SIZE).decode('utf8'))
            msg_bytes = self.tcp_sock.recv(msg_len)
            msg = json.loads(msg_bytes.decode('utf8'))
            return msg
        except:
            print(f'msg_bytes = {msg_bytes}')
            raise Exception('Failed to receive message')

    def tcp_send(self, message):
        try:
            encoded_msg = json.dumps(message).encode('utf8')
            header = f'{len(encoded_msg)}'.ljust(Constants.HEADER_SIZE).encode('utf8')
            self.tcp_sock.send(header+encoded_msg)
        except Exception as e:
            print(f'Message cannot be encode: {e}')
        pass
    
    def read_file(self, filename: str) -> None:
        file_bytes = None
        self.filepath = filename
        with open(filename, 'rb') as f:
            file_bytes = f.read()
        self.file_bytes = file_bytes
        print(f'finished reading {filename}')

    def connect_to_server(self):
        self.tcp_sock.connect((self.ip, self.tcp))
        print('Server is ready to receive file')
        
        return None
        
    def rbudp_send(self, chunksize, blastsize):
        self.read_file('/Users/simon/Developer/share/handin2/book.pdf')
        if not hasattr(self, 'file_bytes'):
            raise Exception('You have to read the file before you can send it')

        chunksize = chunksize
        blastsize = blastsize
        chunks = []
        for i in range(0, len(self.file_bytes), chunksize):
            chunk = self.file_bytes[i:i+chunksize]
            chunks.append({ 
                        'id': int(i/chunksize), 
                        'payload': chunk, 
                        })
        totalchunks = len(chunks)
        if self.set_progress_bar:
            self.set_progress_bar(0)
        transfer_id = uuid.uuid4().hex
        msg = {
            'code': Constants.START_RBUDP_TRANSFER,
            'metadata': {
                'chunksize': chunksize,
                'total_chunks': totalchunks,
                'blastsize': blastsize,
                'filename': self.filepath.split('/')[-1],
                'transfer_id': transfer_id
            }
        }
        print(msg)
        self.tcp_send(msg)
        self.tcp_recv()
        while len(chunks) > 0:
            self.send_blast(blastsize, chunks, totalchunks, transfer_id)

    def send_blast(self, blastsize, chunks, totalchunks, transfer_id):
        for i in range(min(blastsize, len(chunks))):
            id, payload = chunks[i]['id'], chunks[i]['payload']
            if i != 0 and i % 100 == 0:
                continue
            self.udp_send({ 'id': id, 'payload': payload, 'transfer_id': transfer_id })
        self.tcp_send({ 'code': Constants.BLAST_END })
        received_ids = self.tcp_recv()
        for id in received_ids:
            for i in range(len(chunks)):
                if chunks[i]['id'] == id:
                    chunks.pop(i)
                    break
        progress = (totalchunks - len(chunks)) / totalchunks
        if self.set_progress_bar:
            self.set_progress_bar(int(100*progress))
        # time.sleep(0.2)
        print(f'progress = {int(100*progress)}')
        print(f'Number of chunks to send = {len(chunks)}')

    def tcp_file_send(self):
        if self.set_progress_bar:
            self.set_progress_bar(0)
        if not hasattr(self, 'file_bytes'):
            raise Exception('You have to read the file before you can send it')
        msg = { 
            'code': Constants.START_TCP_TRANSFER,
            'metadata': {
                'filename': self.filepath.split('/')[-1],
                'chunksize': Constants.CHUNKS_SIZE,
                'total_chunks': math.ceil(len(self.file_bytes)/Constants.CHUNKS_SIZE),
                'filesize': len(self.file_bytes)
            }
        }
        self.tcp_send(msg)
        for i in range(0, len(self.file_bytes), Constants.CHUNKS_SIZE):
            chunk = self.file_bytes[i:i+Constants.CHUNKS_SIZE]
            print(f'sending {i}:{i+Constants.CHUNKS_SIZE}')
            self.tcp_sock.send(chunk)
            progress = int(100*(i+Constants.CHUNKS_SIZE)/len(self.file_bytes))
            if self.set_progress_bar:
                self.set_progress_bar(progress)

    def ping_server(self, update_ui_func):
        start = time.time()
        self.tcp_send({ 'code': Constants.PING })
        msg = self.tcp_recv()
        if 'code' not in msg:
            print('Code not found in message')
            return None
        if msg['code'] != Constants.MESSAGE_OK:
            print('Message status not ok')
            return None
        elapsed = 1000*(time.time() - start)
        print(f'ping took {elapsed}ms')
        update_ui_func(f'{int(elapsed)}ms')
    

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = SenderGUI()
    sys.exit(app.exec())
