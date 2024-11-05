import sys
from PyQt6.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QGridLayout, QTextEdit

def is_valid_ipv4(ip):
    # Verificar si la IP tiene 4 octetos en el rango 0-255
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    return True

def is_valid_ipv6_mapped(ip):
    # Verificar si la IPv6 está en formato "IPv4-mapped", es decir, ::ffff:xxxx:xxxx
    if ip.lower().startswith("::ffff:"):
        ipv4_part = ip[7:]
        hex_parts = ipv4_part.split(":")
        if len(hex_parts) == 2:
            try:
                # Convertir cada parte hexadecimal y verificar que esté en rango IPv4
                part1 = int(hex_parts[0], 16)
                part2 = int(hex_parts[1], 16)
                return 0 <= part1 <= 65535 and 0 <= part2 <= 65535
            except ValueError:
                return False
    return False

def ipv4_to_ipv6(ipv4):
    # Convertir IPv4 a IPv6 en formato mapeado: ::ffff:x.x.x.x
    parts = ipv4.split(".")
    ipv6_parts = [f"{int(parts[0]):02x}{int(parts[1]):02x}", f"{int(parts[2]):02x}{int(parts[3]):02x}"]
    return f"::ffff:{ipv6_parts[0]}:{ipv6_parts[1]}"

def ipv6_to_ipv4(ipv6):
    # Extraer y convertir la parte IPv4 de una dirección IPv6 mapeada en formato hexadecimal (::ffff:xxxx:xxxx)
    ipv4_part = ipv6[7:]
    hex_parts = ipv4_part.split(":")
    if len(hex_parts) == 2:
        # Convertir cada parte hexadecimal a decimal y formar la dirección IPv4
        part1 = int(hex_parts[0], 16)
        part2 = int(hex_parts[1], 16)
        return f"{part1 >> 8}.{part1 & 0xff}.{part2 >> 8}.{part2 & 0xff}"

class IPConverter(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Conversor IPv4 / IPv6")
        layout = QGridLayout()

        # Cuadro de IPv4 a IPv6
        self.ipv4_label = QLabel("Dirección IPv4:")
        self.ipv4_input = QLineEdit("192.168.1.1")
        self.to_ipv6_button = QPushButton("Convertir a IPv6")
        self.to_ipv6_button.clicked.connect(self.convert_to_ipv6)
        
        layout.addWidget(self.ipv4_label, 0, 0)
        layout.addWidget(self.ipv4_input, 0, 1)
        layout.addWidget(self.to_ipv6_button, 0, 2)

        # Cuadro de IPv6 a IPv4
        self.ipv6_label = QLabel("Dirección IPv6:")
        self.ipv6_input = QLineEdit("::ffff:c0a8:0101")  # Ejemplo en formato hexadecimal
        self.to_ipv4_button = QPushButton("Convertir a IPv4")
        self.to_ipv4_button.clicked.connect(self.convert_to_ipv4)
        
        layout.addWidget(self.ipv6_label, 1, 0)
        layout.addWidget(self.ipv6_input, 1, 1)
        layout.addWidget(self.to_ipv4_button, 1, 2)

        # Área de resultados
        self.results = QTextEdit()
        self.results.setReadOnly(True)
        layout.addWidget(self.results, 2, 0, 1, 3)

        self.setLayout(layout)

    def convert_to_ipv6(self):
        ipv4 = self.ipv4_input.text().strip()
        
        if is_valid_ipv4(ipv4):
            ipv6 = ipv4_to_ipv6(ipv4)
            self.results.setPlainText(f"IPv4: {ipv4}\nIPv6 Mapeado: {ipv6}")
        else:
            self.results.setPlainText("Error: La dirección IPv4 no es válida.")

    def convert_to_ipv4(self):
        ipv6 = self.ipv6_input.text().strip()
        
        if is_valid_ipv6_mapped(ipv6):
            ipv4 = ipv6_to_ipv4(ipv6)
            self.results.setPlainText(f"IPv6: {ipv6}\nIPv4 Convertida: {ipv4}")
        else:
            self.results.setPlainText("Error: La dirección IPv6 no es válida o no está en formato IPv4-mapped (::ffff:xxxx:xxxx).")

if __name__ == "__main__":import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QGridLayout, QTextEdit
)

def ip_to_bin(ip):
    # Convertir cada octeto de la IP a binario con 8 bits
    return ".".join(f"{int(octet):08b}" for octet in ip.split("."))

def apply_netmask(ip, mask_bits):
    # Aplicar la máscara a la dirección IP para obtener la red
    ip_binary = "".join(f"{int(octet):08b}" for octet in ip.split("."))
    masked_ip = ip_binary[:mask_bits] + '0' * (32 - mask_bits)
    return ".".join(str(int(masked_ip[i:i+8], 2)) for i in range(0, 32, 8))

def highlight_network_and_borrowed_bits(ip_bin, mask_bits):
    # Resalta los bits de red y los bits prestados en binario
    highlighted_ip = ""
    for i, bit in enumerate(ip_bin.replace(".", "")):
        if i < mask_bits:
            # Resaltar los bits de red en verde
            highlighted_ip += f'<span style="color: green;">{bit}</span>'
        elif i < mask_bits + (8 - mask_bits % 8):
            # Resaltar los bits prestados en azul
            highlighted_ip += f'<span style="color: blue;">{bit}</span>'
        else:
            # Los bits restantes no tienen resaltado
            highlighted_ip += bit
        if (i + 1) % 8 == 0 and i < len(ip_bin.replace(".", "")) - 1:
            highlighted_ip += "."
    return highlighted_ip

class SubnetCalculator(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Calculadora IP")
        layout = QGridLayout()

        self.ip_label = QLabel("Dirección IP:")
        self.ip_input = QLineEdit("192.168.1.0")
        layout.addWidget(self.ip_label, 0, 0)
        layout.addWidget(self.ip_input, 0, 1)

        self.netmask_label = QLabel("Máscara de red (bits):")
        self.netmask_input = QLineEdit("24")
        layout.addWidget(self.netmask_label, 1, 0)
        layout.addWidget(self.netmask_input, 1, 1)

        self.calculate_button = QPushButton("Calcular")
        layout.addWidget(self.calculate_button, 2, 0, 1, 2)
        self.calculate_button.clicked.connect(self.calculate_subnet)

        self.results = QTextEdit()
        self.results.setReadOnly(True)
        layout.addWidget(self.results, 3, 0, 1, 2)

        self.setLayout(layout)

    def calculate_subnet(self):
        try:
            ip = self.ip_input.text()
            mask_bits = int(self.netmask_input.text())
            
            # Calcular la red aplicando la máscara
            network_ip = apply_netmask(ip, mask_bits)
            
            # Convertir las direcciones a binario para mostrar
            ip_bin = ip_to_bin(ip)
            network_bin = ip_to_bin(network_ip)

            # Resaltar bits de red y bits prestados
            highlighted_network_bin = highlight_network_and_borrowed_bits(network_bin, mask_bits)

            # Mostrar los resultados con estilos en HTML
            result_text = (
                f"<b>IP Original:</b> {ip} ({ip_bin})<br>"
                f"<b>Red calculada:</b> {network_ip} ({highlighted_network_bin})<br>"
                f"<b>Máscara de red:</b> {mask_bits} bits<br>"
            )
            self.results.setHtml(result_text)
        except ValueError:
            self.results.setPlainText("Error: Revisa que los datos sean válidos.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SubnetCalculator()
    window.resize(600, 400)
    window.show()
    sys.exit(app.exec())

    app = QApplication(sys.argv)
    window = IPConverter()
    window.resize(500, 200)
    window.show()
    sys.exit(app.exec())
