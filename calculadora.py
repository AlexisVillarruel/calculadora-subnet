import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QTextEdit, QVBoxLayout, QWidget
)


def ip_to_binary(ip):
    octetos = ip.split(".")
    binario = ""
    for octeto in octetos:
        binario += f"{int(octeto):08b}"
    return binario


def binary_to_ip(binario):
    ip = []
    for i in range(0, len(binario), 8):
        ip.append(str(int(binario[i:i+8], 2)))
    return ".".join(ip)


def calculate_wildcard(mask_bits):
    wildcard = ""
    for i in range(32):
        if i < mask_bits:
            wildcard += "0"
        else:
            wildcard += "1"
    return binary_to_ip(wildcard)


def subnet_details(ip, mask_bits, new_mask_bits):
    ip_binario = ip_to_binary(ip)
    base_network = ip_binario[:mask_bits]
    subnets = 2 ** (new_mask_bits - mask_bits)
    results = []

    for i in range(subnets):
        subnet_bin = base_network + f"{i:0{new_mask_bits - mask_bits}b}" + "0" * (32 - new_mask_bits)
        network_ip = binary_to_ip(subnet_bin)

        broadcast_bin = subnet_bin[:new_mask_bits] + "1" * (32 - new_mask_bits)
        broadcast_ip = binary_to_ip(broadcast_bin)

        first_host_bin = subnet_bin[:new_mask_bits] + "0" * (31 - new_mask_bits) + "1"
        first_host_ip = binary_to_ip(first_host_bin)

        last_host_bin = broadcast_bin[:32 - 1] + "0"
        last_host_ip = binary_to_ip(last_host_bin)

        hosts_count = (2 ** (32 - new_mask_bits)) - 2

        results.append({
            "network_ip": network_ip,
            "broadcast_ip": broadcast_ip,
            "first_host_ip": first_host_ip,
            "last_host_ip": last_host_ip,
            "hosts_count": hosts_count
        })

    return results


class SubnetCalculator(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Calculadora de Subredes")
        self.setGeometry(100, 100, 600, 400)

        # Widgets
        self.layout = QVBoxLayout()
        self.container = QWidget()

        self.ip_label = QLabel("Dirección IP:")
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Ejemplo: 192.168.0.0")

        self.mask_label = QLabel("Máscara original (ej. 24):")
        self.mask_input = QLineEdit()
        self.mask_input.setPlaceholderText("24")

        self.new_mask_label = QLabel("Nueva máscara (ej. 26):")
        self.new_mask_input = QLineEdit()
        self.new_mask_input.setPlaceholderText("26")

        self.calculate_button = QPushButton("Calcular")
        self.calculate_button.clicked.connect(self.calculate_subnets)

        self.results_box = QTextEdit()
        self.results_box.setReadOnly(True)

        # Agregar widgets al layout
        self.layout.addWidget(self.ip_label)
        self.layout.addWidget(self.ip_input)
        self.layout.addWidget(self.mask_label)
        self.layout.addWidget(self.mask_input)
        self.layout.addWidget(self.new_mask_label)
        self.layout.addWidget(self.new_mask_input)
        self.layout.addWidget(self.calculate_button)
        self.layout.addWidget(self.results_box)

        # Configurar contenedor
        self.container.setLayout(self.layout)
        self.setCentralWidget(self.container)

    def calculate_subnets(self):
        ip = self.ip_input.text()
        try:
            mask_bits = int(self.mask_input.text())
            new_mask_bits = int(self.new_mask_input.text())

            if new_mask_bits <= mask_bits or new_mask_bits > 30:
                self.results_box.setPlainText("La nueva máscara debe ser mayor a la original y menor o igual a /30.")
                return

            wildcard = calculate_wildcard(mask_bits)
            subnets = subnet_details(ip, mask_bits, new_mask_bits)

            results = f"Address: {ip}/{mask_bits}\n"
            netmask = ".".join([str((0xFFFFFFFF << (32 - mask_bits) >> i) & 0xFF) for i in [24, 16, 8, 0]])
            results += f"Netmask: {netmask}\n"
            results += f"Wildcard: {wildcard}\n\n"

            for i, subnet in enumerate(subnets, start=1):
                results += (
                    f"Subred {i}:\n"
                    f"  Network: {subnet['network_ip']}/{new_mask_bits}\n"
                    f"  Broadcast: {subnet['broadcast_ip']}\n"
                    f"  HostMin: {subnet['first_host_ip']}\n"
                    f"  HostMax: {subnet['last_host_ip']}\n"
                    f"  Hosts disponibles: {subnet['hosts_count']}\n\n"
                )

            self.results_box.setPlainText(results)
        except ValueError:
            self.results_box.setPlainText("Error: Verifica que los datos ingresados sean válidos.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SubnetCalculator()
    window.show()
    sys.exit(app.exec())
