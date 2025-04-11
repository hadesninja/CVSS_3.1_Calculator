from PyQt5.QtWidgets import (QApplication, QWidget, QLabel, QComboBox, QPushButton, QGridLayout, QVBoxLayout, QLineEdit, QMainWindow, QAction, QMessageBox, QHBoxLayout)
from PyQt5.QtGui import QColor
from PyQt5.QtCore import Qt
from cvss import CVSS3  # Install with: pip install cvss

class CVSSCalculator(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
    
    def initUI(self):
        self.setWindowTitle("CVSS 3.1 Calculator")
        self.setGeometry(100, 100, 500, 500)
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QGridLayout()
        
        self.labels = {
            "Attack Vector": "AV", "Attack Complexity": "AC", "Privileges Required": "PR", "User Interaction": "UI",
            "Scope": "S", "Confidentiality": "C", "Integrity": "I", "Availability": "A"
        }
        self.options = {
            "Attack Vector": {"Network (N)": "N", "Adjacent (A)": "A", "Local (L)": "L", "Physical (P)": "P"},
            "Attack Complexity": {"Low (L)": "L", "High (H)": "H"},
            "Privileges Required": {"None (N)": "N", "Low (L)": "L", "High (H)": "H"},
            "User Interaction": {"None (N)": "N", "Required (R)": "R"},
            "Scope": {"Unchanged (U)": "U", "Changed (C)": "C"},
            "Confidentiality": {"None (N)": "N", "Low (L)": "L", "High (H)": "H"},
            "Integrity": {"None (N)": "N", "Low (L)": "L", "High (H)": "H"},
            "Availability": {"None (N)": "N", "Low (L)": "L", "High (H)": "H"}
        }
        
        self.info_texts = {
             "Attack Vector": "This metric reflects the context by which vulnerability exploitation is possible. The Base Score increases the more remote (logically, and physically) an attacker can be in order to exploit the vulnerable component.\n\n- Network (N): The vulnerable component is bound to the network stack and the set of possible attackers extends beyond the other options listed, up to and including the entire Internet. Such a vulnerability is often termed remotely exploitable and can be thought of as an attack being exploitable at the protocol level one or more network hops away (e.g., across one or more routers).\n\n- Adjacent (A): The vulnerable component is bound to the network stack, but the attack is limited at the protocol level to a logically adjacent topology. This can mean an attack must be launched from the same shared physical (e.g., Bluetooth or IEEE 802.11) or logical (e.g., local IP subnet) network, or from within a secure or otherwise limited administrative domain (e.g., MPLS, secure VPN to an administrative network zone).\n\n- Local (L): The vulnerable component is not bound to the network stack and the attacker’s path is via read/write/execute capabilities. Either: the attacker exploits the vulnerability by accessing the target system locally (e.g., keyboard, console), or remotely (e.g., SSH); or the attacker relies on User Interaction by another person to perform actions required to exploit the vulnerability (e.g., tricking a legitimate user into opening a malicious document).\n\n- Physical (P): The attack requires the attacker to physically touch or manipulate the vulnerable component. Physical interaction may be brief or persistent.",

            "Attack Complexity": "This metric describes the conditions beyond the attacker’s control that must exist in order to exploit the vulnerability. Such conditions may require the collection of more information about the target or computational exceptions. The assessment of this metric excludes any requirements for user interaction in order to exploit the vulnerability. If a specific configuration is required for an attack to succeed, the Base metrics should be scored assuming the vulnerable component is in that configuration.\n\n- Low (L): Specialized access conditions or extenuating circumstances do not exist. An attacker can expect repeatable success against the vulnerable component.\n\n- High (H): A successful attack depends on conditions beyond the attackers control. That is, a successful attack cannot be accomplished at will, but requires the attacker to invest in some measurable amount of effort in preparation or execution against the vulnerable component before a successful attack can be expected. For example, a successful attack may require an attacker to: gather knowledge about the environment in which the vulnerable target/component exists prepare the target environment to improve exploit reliability; or inject themselves into the logical network path between the target and the resource requested by the victim in order to read and/or modify network communications (e.g. a man in the middle attack).",

            "Privileges Required": "This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability.\n\n- None (N): The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files to carry out an attack.\n\n- Low (L): The attacker is authorized with (i.e., requires) privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. Alternatively, an attacker with Low privileges may have the ability to cause an impact only to non-sensitive resources.\n\n- High (H): The attacker is authorized with (i.e., requires) privileges that provide significant (e.g., administrative) control over the vulnerable component that could affect component-wide settings and files.",

            "User Interaction": "This metric captures the requirement for a user, other than the attacker, to participate in the successful compromise the vulnerable component. This metric determines whether the vulnerability can be exploited solely at the will of the attacker, or whether a separate user (or user-initiated process) must participate in some manner.\n\n- None (N): The vulnerable system can be exploited without any interaction from any user.\n\n- Required (R): Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited.",

            "Scope": "Does a successful attack impact a component other than the vulnerable component? If so, the Base Score increases and the Confidentiality, Integrity and Authentication metrics should be scored relative to the impacted component.\n\n- Unchanged (U): An exploited vulnerability can only affect resources managed by the same security authority. In this case, the vulnerable component and the impacted component are either the same, or both are managed by the same security authority.\n\n- Changed (C): An exploited vulnerability can affect resources beyond the security scope managed by the security authority of the vulnerable component. In this case, the vulnerable component and the impacted component are different and managed by different security authorities.",

            "Confidentiality": "This metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized ones.\n\n- None (N): There is no loss of confidentiality within the impacted component.\n\n- Low (L): There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is limited. The information disclosure does not cause a direct, serious loss to the impacted component.\n\n- High (H): There is total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. Alternatively, access to only some restricted information is obtained, but the disclosed information presents a direct, serious impact.",

            "Integrity": "This metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information.\n\n- None (N): There is no loss of integrity within the impacted component.\n\n- Low (L): Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is limited. The data modification does not have a direct, serious impact on the impacted component.\n\n- High (H): There is a total loss of integrity, or a complete loss of protection. For example, the attacker is able to modify any/all files protected by the impacted component. Alternatively, only some files can be modified, but malicious modification would present a direct, serious consequence to the impacted component.",

            "Availability": "This metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. It refers to the loss of availability of the impacted component itself, such as a networked service (e.g., web, database, email). Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of an impacted component.\n\n- None (N): There is no impact to availability within the impacted component.\n\n- Low (L): Performance is reduced or there are interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. The resources in the impacted component are either partially available all of the time, or fully available only some of the time, but overall there is no direct, serious consequence to the impacted component.\n\n- High (H): There is total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed)."
}

        
        self.combos = {}
        
        for i, (label, short) in enumerate(self.labels.items()):
            row_layout = QHBoxLayout()
            lbl = QLabel(label, self)
            
            info_button = QPushButton("i", self)
            info_button.setFixedSize(20, 20)
            info_button.clicked.connect(lambda checked, lbl=label: self.show_info(lbl))
            
            combo = QComboBox(self)
            for option, value in self.options[label].items():
                combo.addItem(option)
            
            row_layout.addWidget(lbl)
            row_layout.addWidget(info_button)
            row_layout.addStretch()  # Push items to left
            
            self.layout.addLayout(row_layout, i, 0)  # Label + Info Button in column 0
            self.layout.addWidget(combo, i, 1)  # Dropdown in column 1
            
            self.combos[label] = combo
        
        self.calc_button = QPushButton("Calculate CVSS Score", self)
        self.calc_button.clicked.connect(self.calculate_cvss)
        self.layout.addWidget(self.calc_button, len(self.labels), 0, 1, 2)
        
        self.result_label = QLabel("CVSS Score: ", self)
        self.result_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.result_label, len(self.labels) + 1, 0, 1, 2)
        
        self.vector_output = QLineEdit(self)
        self.vector_output.setReadOnly(True)
        self.vector_output.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.vector_output, len(self.labels) + 2, 0, 1, 1)
        
        self.copy_button = QPushButton("Copy", self)
        self.copy_button.clicked.connect(self.copy_to_clipboard)
        self.layout.addWidget(self.copy_button, len(self.labels) + 2, 1, 1, 1)
        
        self.central_widget.setLayout(self.layout)
        
        self.create_menu()
    
    def create_menu(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")
        help_menu = menubar.addMenu("Help")
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def show_about(self):
        QMessageBox.information(self, "About", "Developer: Vaibhav Patil\nVersion: 1.0")
    
    def show_info(self, label):
        QMessageBox.information(self, label, f"{self.info_texts[label]}\n\n")
    
    def calculate_cvss(self):
        try:
            vector = "CVSS:3.1/" + "/".join([
                f"{self.labels[label]}:{self.options[label][self.combos[label].currentText()]}" for label in self.labels
            ])
            score = CVSS3(vector).scores()[0]
            self.result_label.setText(f"CVSS Score: {score:.1f}")
            self.vector_output.setText(vector)
            self.set_severity_color(score)
        except Exception:
            self.result_label.setText("Error: Invalid CVSS Calculation")
            self.vector_output.setText("")
    
    def set_severity_color(self, score):
        colors = {9: "#d32f2f", 7: "#ffa000", 4: "#fbc02d", 0: "#388e3c"}
        color = next((c for s, c in colors.items() if score >= s), "#9e9e9e")
        self.result_label.setStyleSheet(f"color: white; background-color: {color}; padding: 5px; border-radius: 5px;")
    
    def copy_to_clipboard(self):
        QApplication.clipboard().setText(self.vector_output.text())

if __name__ == '__main__':
    app = QApplication([])
    window = CVSSCalculator()
    window.show()
    app.exec_()
