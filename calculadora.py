import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QGridLayout, QTextEdit
)
import ipaddress

def ip_to_bin(ip):
    return ".".join(f"{int(octet):08b}" for octet in ip.split("."))

def ip_to_bin_with_mask_highlight(ip, netmask):
    """
    Convierte una dirección IP a binario y resalta todos los bits '1' de la máscara de red de acuerdo con la longitud del prefijo.
    """
    binary_ip = [f"{int(octet):08b}" for octet in ip.split(".")]
    
    highlighted_ip = []

    for i, octet in enumerate(binary_ip):
        if i == 3:  # Si estamos en el último octeto
            highlighted_octet = "".join(
                f'<span style="color: green;">{bit}</span>' if bit == '1' else bit for bit in octet
            )
        else:
            highlighted_octet = octet

        highlighted_ip.append(highlighted_octet)

    return ".".join(highlighted_ip)

class SubnetCalculator(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Calculadora IP")

        layout = QGridLayout()

        self.ip_label = QLabel("Address (Host or Network):")
        self.ip_input = QLineEdit("192.168.1.0")
        layout.addWidget(self.ip_label, 0, 0)
        layout.addWidget(self.ip_input, 0, 1)

        self.netmask_label = QLabel("Netmask (i.e. 24):")
        self.netmask_input = QLineEdit("24")
        layout.addWidget(self.netmask_label, 1, 0)
        layout.addWidget(self.netmask_input, 1, 1)

        self.subnet_label = QLabel("Netmask for sub/supernet (optional):")
        self.subnet_input = QLineEdit("27")
        layout.addWidget(self.subnet_label, 2, 0)
        layout.addWidget(self.subnet_input, 2, 1)

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
            netmask = int(self.netmask_input.text())
            new_subnet_mask = self.subnet_input.text()

            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            wildcard = network.hostmask

            net_bin = ip_to_bin(str(network.network_address))
            mask_bin = ip_to_bin_with_mask_highlight(str(network.netmask), netmask)
            wildcard_bin = ip_to_bin(str(wildcard))
            broadcast_bin = ip_to_bin(str(network.broadcast_address))

            result_text = (
                f"<style>"
                f"    .spaced {{ padding-left: 20px; }} "
                f"</style>"
                f"<b>Network:</b> {network.network_address}/{netmask} <span class='spaced'>{net_bin}</span><br>"
                f"<b>Netmask:</b> {network.netmask} = {netmask} <span class='spaced'>{mask_bin}</span><br>"
                f"<b>Wildcard:</b> {wildcard} <span class='spaced'>{wildcard_bin}</span><br>"
                f"<b>HostMin:</b> {network[1]} <span class='spaced'>{ip_to_bin(str(network[1]))}</span><br>"
                f"<b>HostMax:</b> {network[-2]} <span class='spaced'>{ip_to_bin(str(network[-2]))}</span><br>"
                f"<b>Broadcast:</b> {network.broadcast_address} <span class='spaced'>{broadcast_bin}</span><br>"
                f"<b>Hosts/Net:</b> {network.num_addresses - 2}<br>"
            )

            if new_subnet_mask:
                try:
                    subnet_prefix = int(new_subnet_mask)
                    if subnet_prefix > netmask:
                        subnets = list(network.subnets(new_prefix=subnet_prefix))
                        subnet_mask = ipaddress.IPv4Network(f"0.0.0.0/{subnet_prefix}").netmask
                        subnet_mask_bin = ip_to_bin_with_mask_highlight(str(subnet_mask), subnet_prefix)

                        result_text += (
                            f"<br><b>Subnets after transition from /{netmask} to /{subnet_prefix}</b><br>"
                            f"<b>Netmask:</b> {subnet_mask} = {subnet_prefix} <span class='spaced'>{subnet_mask_bin}</span><br>"
                        )

                        for i, subnet in enumerate(subnets, start=1):
                            subnet_bin = ip_to_bin(str(subnet.network_address))
                            host_min_bin = ip_to_bin(str(subnet[1]))
                            host_max_bin = ip_to_bin(str(subnet[-2]))
                            broadcast_sub_bin = ip_to_bin(str(subnet.broadcast_address))

                            network_bits = subnet_bin.split(".")
                            net_segment = ".".join(network_bits[:-1])
                            last_segment = network_bits[-1]

                            num_network_bits = netmask
                            num_borrowed_bits = subnet_prefix - netmask

                            highlighted_last_segment = (
                                f'<span style="color: blue;">{last_segment[:num_network_bits % 8]}</span>'
                                f'<span style="color: red;">{last_segment[num_network_bits % 8:num_network_bits % 8 + num_borrowed_bits]}</span>'
                                f'<span style="color: black;">{last_segment[num_network_bits % 8 + num_borrowed_bits:]}</span>'
                            )

                            highlighted_subnet_bin = f"{net_segment}.{highlighted_last_segment}"

                            result_text += (
                                f"{i}. <b>Network:</b> {subnet.network_address}/{subnet_prefix} <span class='spaced'>{highlighted_subnet_bin}</span><br>"
                                f"&nbsp;&nbsp;&nbsp;<b>HostMin:</b> {subnet[1]} <span class='spaced'>{host_min_bin}</span><br>"
                                f"&nbsp;&nbsp;&nbsp;<b>HostMax:</b> {subnet[-2]} <span class='spaced'>{host_max_bin}</span><br>"
                                f"&nbsp;&nbsp;&nbsp;<b>Broadcast:</b> {subnet.broadcast_address} <span class='spaced'>{broadcast_sub_bin}</span><br>"
                                f"&nbsp;&nbsp;&nbsp;<b>Hosts/Net:</b> {subnet.num_addresses - 2}<br><br>"
                            )
                except ValueError:
                    result_text += "<br>Error: Netmask for sub/supernet must be a valid integer.<br>"

            self.results.setHtml(result_text)
        except ValueError as e:
            self.results.setText(f"Error: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = SubnetCalculator()
    window.resize(800, 600)
    window.show()

    sys.exit(app.exec())
#pip install PyQt6
#pip install ipaddress