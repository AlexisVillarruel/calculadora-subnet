import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QGridLayout, QTextEdit
)
from PyQt6.QtGui import QTextCursor

def ip_to_bin(ip):
    return ".".join(f"{int(octet):08b}" for octet in ip.split("."))

def apply_netmask(ip, mask_bits):
    ip_binary = "".join(f"{int(octet):08b}" for octet in ip.split("."))
    masked_ip = ip_binary[:mask_bits] + '0' * (32 - mask_bits)
    return ".".join(str(int(masked_ip[i:i+8], 2)) for i in range(0, 32, 8))

def calculate_hosts(mask_bits):
    return (2 ** (32 - mask_bits)) - 2

def calculate_broadcast(network_ip_bin, mask_bits):
    broadcast_bin = network_ip_bin[:mask_bits] + '1' * (32 - mask_bits)
    return ".".join(str(int(broadcast_bin[i:i+8], 2)) for i in range(0, 32, 8))

def calculate_subnets(ip, original_mask_bits, new_mask_bits):
    ip_binary = "".join(f"{int(octet):08b}" for octet in ip.split("."))
    base_network = ip_binary[:original_mask_bits]
    num_subnets = 2 ** (new_mask_bits - original_mask_bits)
    
    subnets = []
    for i in range(num_subnets):
        subnet_bin = base_network + f"{i:0{new_mask_bits - original_mask_bits}b}" + '0' * (32 - new_mask_bits)
        network_ip = ".".join(str(int(subnet_bin[j:j+8], 2)) for j in range(0, 32, 8))
        
        host_min_bin = subnet_bin[:32 - (32 - new_mask_bits)] + '0' * (32 - new_mask_bits)
        host_min = ".".join(str(int(host_min_bin[j:j+8], 2)) for j in range(0, 32, 8))
        host_min = host_min.split('.')
        host_min[3] = str(int(host_min[3]) + 1)
        
        broadcast_ip = calculate_broadcast(subnet_bin, new_mask_bits)
        
        host_max = broadcast_ip.split('.')
        host_max[3] = str(int(host_max[3]) - 1)
        
        hosts_count = calculate_hosts(new_mask_bits)
        
        subnets.append({
            "network_ip": network_ip,
            "host_min": ".".join(host_min),
            "host_max": ".".join(host_max),
            "broadcast_ip": broadcast_ip,
            "hosts_count": hosts_count,
            "network_bin": format_binary_ipv4(subnet_bin, new_mask_bits, original_mask_bits)
        })
    
    return subnets

def format_binary_ipv4(bin_ip, mask_bits, original_mask_bits):
    # Formatea y resalta los bits de red, prestados y de host en binario para IPv4 completo
    red_bits = f"<span style='color:green'>{bin_ip[:original_mask_bits]}</span>"
    borrowed_bits = f"<span style='color:red'>{bin_ip[original_mask_bits:mask_bits]}</span>"
    host_bits = f"<span style='color:gray'>{bin_ip[mask_bits:]}</span>"
    highlighted = red_bits + borrowed_bits + host_bits
    # Dividir en bloques de 8 bits con puntos para simular el formato IPv4 completo en binario
    return ".".join(highlighted[i:i+8] for i in range(0, 32, 8))

class SubnetCalculator(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Calculadora IP")
        layout = QGridLayout()

        self.ip_label = QLabel("Dirección IP (Host o Red):")
        self.ip_input = QLineEdit("192.168.0.1")
        layout.addWidget(self.ip_label, 0, 0)
        layout.addWidget(self.ip_input, 0, 1)

        self.original_mask_label = QLabel("Máscara (ej. 24):")
        self.original_mask_input = QLineEdit("24")
        layout.addWidget(self.original_mask_label, 1, 0)
        layout.addWidget(self.original_mask_input, 1, 1)

        self.new_mask_label = QLabel("Mover a (nueva máscara):")
        self.new_mask_input = QLineEdit("25")
        layout.addWidget(self.new_mask_label, 2, 0)
        layout.addWidget(self.new_mask_input, 2, 1)

        self.calculate_button = QPushButton("Calcular")
        layout.addWidget(self.calculate_button, 3, 0, 1, 2)
        self.calculate_button.clicked.connect(self.calculate_subnet)

        self.results = QTextEdit()
        self.results.setReadOnly(True)
        layout.addWidget(self.results, 4, 0, 1, 2)

        self.setLayout(layout)

    def calculate_subnet(self):
        try:
            ip = self.ip_input.text()
            original_mask_bits = int(self.original_mask_input.text())
            new_mask_bits = int(self.new_mask_input.text())

            if new_mask_bits <= original_mask_bits or new_mask_bits > 30:
                self.results.setPlainText("La nueva máscara debe estar entre la original y un valor máximo de /30.")
                return

            subnets = calculate_subnets(ip, original_mask_bits, new_mask_bits)

            result_text = f"<b>División de subredes de /{original_mask_bits} a /{new_mask_bits}:</b><br><br>"
            for i, subnet in enumerate(subnets, start=1):
                result_text += (
                    f"<b>Subred {i}:</b><br>"
                    f"Network: {subnet['network_ip']} ({subnet['network_bin']})<br>"
                    f"HostMin: {subnet['host_min']}<br>"
                    f"HostMax: {subnet['host_max']}<br>"
                    f"Broadcast: {subnet['broadcast_ip']}<br>"
                    f"Hosts/Net: {subnet['hosts_count']}<br><br>"
                )

            self.results.setHtml(result_text)
            self.results.moveCursor(QTextCursor.MoveOperation.Start)
        except ValueError:
            self.results.setPlainText("Error: Verifica que los datos ingresados sean válidos.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SubnetCalculator()
    window.resize(600, 400)
    window.show()
    sys.exit(app.exec())
