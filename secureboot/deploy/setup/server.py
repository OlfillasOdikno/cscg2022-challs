from os import fdopen
import socketserver, tempfile
import pty, os
import shutil
import signal
from glob import glob
import selectors

bootloader_test = os.path.abspath("bootloader_test")
bootloader_prod = os.path.abspath("bootloader_prod")

flag1 = os.getenv("FLAG1", "CSCG{TESTFLAG1}")
flag2 = os.getenv("FLAG2", "CSCG{TESTFLAG2}")
flag3 = os.getenv("FLAG3", "CSCG{TESTFLAG3}")

testsigned_signatures = []
for p in glob("./testsigned_images/*"):
    with open(p,"rb") as f:
        data = f.read()
    signature = data[-8:]
    testsigned_signatures.append(signature)

TIMEOUT = 60*10 #timeout after ten minutes
class Handler(socketserver.BaseRequestHandler):
    def recv_line(self):
        buffer = b''
        while b"\n" not in buffer:
            buffer += self.request.recv(1)
        return buffer.strip()

    def handle(self):
        self.request.sendall(f"[?] Please select the bootloader: (default: 0)\n".encode())
        self.request.sendall(f"[0] TEST\n".encode())
        self.request.sendall(f"[1] PRODUCTION\n".encode())
        if self.recv_line() == b"1":
            self.request.sendall(f"[*] loading production bootloader..\n".encode())
            bootloader = bootloader_prod
        else:
            self.request.sendall(f"[*] loading test bootloader..\n".encode())
            bootloader = bootloader_test

        self.request.sendall(f"[?] Please select the display mode: (default: 0)\n".encode())
        self.request.sendall(f"[0] GRAPHIC\n".encode())
        self.request.sendall(f"[1] NOGRAPHIC\n".encode())
        if self.recv_line() == b"1":
            self.request.sendall(f"[*] using no graphic args..\n".encode())
            no_graphic = True
        else:
            self.request.sendall(f"[*] using graphic args..\n".encode())
            no_graphic = False


        self.request.sendall(f"[?] Please provide an image in hex format. (520 bytes)\n".encode())
        self.request.sendall(f"[*] End your input with \"EOF\"\n".encode())

        buffer = b''
        while b"EOF" not in buffer:
            buffer += self.request.recv(1024)
        buffer = buffer.replace(b'EOF',b'').lower()
        try:
            buffer = bytes(list(filter(lambda x: chr(x) in "0123456789abcdef", buffer)))

            data = bytes.fromhex(buffer.decode())
            assert len(data) == 520
        except:
            self.request.sendall(f"[!] invalid input... bye!\n".encode())
            return

        fd, mbr_path = tempfile.mkstemp()
        with fdopen(fd, "wb") as f:
            f.write(data)

        signature = data[-8:]

        if bootloader == bootloader_prod:
            flag = flag3
            self.request.sendall(f"[*] CRY to receive the third flag!\n".encode())
        elif signature not in testsigned_signatures:
            self.request.sendall(f"[*] REV to obtain the second flag!\n".encode())
            flag = flag2
        else:
            self.request.sendall(f"[*] PWN gives the first flag!\n".encode())
            flag = flag1

        fd, flag_path = tempfile.mkstemp()
        with fdopen(fd, "wb") as f:
            f.write(flag.encode())

        fd, bootloader_path = tempfile.mkstemp()
        with open(bootloader, "rb") as f,  fdopen(fd,"wb") as f2:
            shutil.copyfileobj(f, f2)

        cmd = [
            '/usr/bin/qemu-system-i386', 
            '-drive', f'format=raw,file={bootloader_path}', 
            '-drive', f'format=raw,file={mbr_path}', 
            '-drive', f'format=raw,file={flag_path}',
            '-display', 'curses',
            '-monitor', 'none',
        ]
        if no_graphic:
            cmd += ['-nographic']

        self.request.sendall(f"[*] Starting qemu, good luck!\n".encode())

        os.dup2(self.request.fileno(),0)
        os.dup2(self.request.fileno(),1)
        os.dup2(self.request.fileno(),2)
        signal.signal(signal.SIGALRM, lambda _n, _f: [self.request.sendall(b"[!] Timed out..\n"),exit(1)])
        signal.alarm(TIMEOUT)
        pty.spawn(cmd)
        #socat file:`tty`,raw,echo=0 tcp:localhost:1024


with socketserver.ForkingTCPServer(("0.0.0.0", 1024), Handler) as server:
    server.allow_reuse_address = True
    with selectors.PollSelector() as selector:
        selector.register(server, selectors.EVENT_READ)
        while True:
            ready = selector.select(0.5)
            if ready:
                server._handle_request_noblock()