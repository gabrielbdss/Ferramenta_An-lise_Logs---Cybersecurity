import sys
import re
import os
import json
import csv
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QPushButton, QVBoxLayout, QTextEdit, QFileDialog, QMessageBox
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

class LogAnalyzerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        """Configura a interface do usuário."""
        self.setWindowTitle("Ferramenta de Análise de Logs - Cybersecurity")
        self.setStyleSheet("background-color: #2C3E50; color: white;")
        self.setGeometry(100, 100, 900, 650)

        # Layout principal
        layout = QVBoxLayout()

        # Botão para selecionar arquivo de log
        self.select_button = QPushButton("Selecionar Arquivo de Log")
        self.style_button(self.select_button, "#1ABC9C", "#16A085")
        self.select_button.clicked.connect(self.select_log_file)
        layout.addWidget(self.select_button)

        # Botões de análise e exportação
        self.analyze_button = QPushButton("Iniciar Análise")
        self.export_button = QPushButton("Exportar Relatório")
        self.analyze_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.style_button(self.analyze_button, "#3498DB", "#2980B9")
        self.style_button(self.export_button, "#E67E22", "#D35400")
        self.analyze_button.clicked.connect(self.start_analysis)
        self.export_button.clicked.connect(self.export_report)
        layout.addWidget(self.analyze_button)
        layout.addWidget(self.export_button)

        # Área de resultados
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setStyleSheet("background-color: #34495E; color: white; border-radius: 5px; padding: 10px;")
        layout.addWidget(self.result_text)

        # Gráfico
        self.fig, self.ax = plt.subplots(figsize=(5, 4))
        self.canvas = FigureCanvas(self.fig)
        self.ax.set_facecolor("#34495E")
        layout.addWidget(self.canvas)

        # Rodapé
        footer = QLabel("Desenvolvido por Gabriel Barbosa | Cybersecurity Portfolio")
        footer.setStyleSheet("color: #F1C40F; text-align: center;")
        layout.addWidget(footer)

        self.setLayout(layout)

    def style_button(self, button, color, hover_color):
        """Aplica estilo aos botões."""
        button.setStyleSheet(f"""
            QPushButton {{
                background-color: {color}; color: white; border-radius: 5px; padding: 10px;
                min-width: 150px; font-size: 14px; font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {hover_color};
            }}
        """)

    def select_log_file(self):
        """Abre um diálogo para selecionar o arquivo de log."""
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Selecionar Arquivo de Log", "", "Log Files (*.log);;All Files (*)", options=options)
        if file_path:
            self.log_file = file_path
            self.analyze_button.setEnabled(True)
            self.result_text.append(f"Arquivo selecionado: {file_path}\n")

    def start_analysis(self):
        """Inicia a análise do arquivo de log."""
        self.analyze_button.setEnabled(False)
        self.export_button.setEnabled(False)
        self.result_text.clear()
        self.ax.clear()
        self.canvas.draw()

        try:
            with open(self.log_file, 'r') as file:
                logs = file.readlines()

            attacks = self.analyze_logs(logs)
            if attacks:
                self.result_text.append("Padrões de ataque detectados:\n")
                for attack, count in attacks.items():
                    self.result_text.append(f"{attack}: {count} ocorrências")
                self.generate_graph(attacks)
            else:
                self.result_text.append("Nenhum padrão de ataque detectado.")

        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Erro ao analisar o arquivo: {e}")
        finally:
            self.analyze_button.setEnabled(True)
            self.export_button.setEnabled(bool(attacks))

    def analyze_logs(self, logs):
        """Analisa os logs para detectar padrões de ataque."""
        patterns = {
            "Força Bruta": re.compile(r"failed login", re.IGNORECASE),
            "Injeção de SQL": re.compile(r"union select", re.IGNORECASE),
            "Varredura": re.compile(r"scan", re.IGNORECASE)
        }
        attack_counts = {key: sum(1 for log in logs if pattern.search(log)) for key, pattern in patterns.items()}
        return {key: val for key, val in attack_counts.items() if val > 0}

    def generate_graph(self, attacks):
        """Gera um gráfico de barras com os ataques detectados."""
        self.ax.bar(attacks.keys(), attacks.values(), color='cyan')
        self.ax.set_xlabel("Tipo de Ataque")
        self.ax.set_ylabel("Ocorrências")
        self.ax.set_title("Análise de Ataques")
        self.canvas.draw()

    def export_report(self):
        """Exporta o relatório para o formato escolhido pelo usuário."""
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Salvar Relatório", "", "Texto (*.txt);;CSV (*.csv);;JSON (*.json);;Todos os Arquivos (*)", options=options)

        if file_path:
            try:
                if file_path.endswith('.txt'):
                    self.save_as_text(file_path)
                elif file_path.endswith('.csv'):
                    self.save_as_csv(file_path)
                elif file_path.endswith('.json'):
                    self.save_as_json(file_path)
                QMessageBox.information(self, "Sucesso", "Relatório exportado com sucesso!")
            except Exception as e:
                QMessageBox.critical(self, "Erro", f"Erro ao exportar relatório: {e}")

    def save_as_text(self, file_path):
        with open(file_path, "w") as file:
            file.write(self.result_text.toPlainText())

    def save_as_csv(self, file_path):
        with open(file_path, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Tipo de Ataque", "Ocorrências"])
            for line in self.result_text.toPlainText().splitlines():
                if ":" in line:
                    writer.writerow(line.split(": "))

    def save_as_json(self, file_path):
        attacks = {line.split(": ")[0]: int(line.split(": ")[1]) for line in self.result_text.toPlainText().splitlines() if ":" in line}
        with open(file_path, "w") as file:
            json.dump(attacks, file, indent=4)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LogAnalyzerApp()
    window.show()
    sys.exit(app.exec_())