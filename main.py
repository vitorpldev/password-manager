import sys
import random
import string
import sqlite3
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, 
    QCheckBox, QGridLayout, QMessageBox, QTableWidget, QTableWidgetItem, 
    QHeaderView, QHBoxLayout, QAbstractItemView
)
from PyQt6.QtCore import Qt

# Função para gerar a senha
def generate_password(length, use_uppercase, use_lowercase, use_numbers, use_symbols):
    characters = ''
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_numbers:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation
    
    if not characters:
        raise ValueError("At least one character type must be selected.")
    
    return ''.join(random.choice(characters) for _ in range(length))

# Função para conectar ao banco de dados
def create_db_connection():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, service TEXT UNIQUE, password TEXT)''')
    conn.commit()
    return conn

# Função para salvar a senha no banco de dados SQLite
def save_password(service, password):
    conn = create_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO passwords (service, password) VALUES (?, ?)", (service, password))
        conn.commit()
    except sqlite3.IntegrityError:
        raise ValueError("A password for this service already exists.")
    finally:
        conn.close()

# Função para atualizar uma senha existente
def update_password(service, new_password):
    conn = create_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE passwords SET password = ? WHERE service = ?", (new_password, service))
    conn.commit()
    conn.close()

# Função para excluir uma senha
def delete_password(service):
    conn = create_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE service = ?", (service,))
    conn.commit()
    conn.close()

# Função para buscar todos os serviços armazenados
def get_all_services():
    conn = create_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT service FROM passwords")
    records = cursor.fetchall()
    conn.close()
    return [record[0] for record in records]

# Função para buscar as senhas armazenadas
def get_all_passwords():
    conn = create_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT service, password FROM passwords")
    records = cursor.fetchall()
    conn.close()
    return records

# Função principal da interface gráfica com PyQt6
class PasswordManager(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 600, 500)
        
        # Layout principal
        layout = QVBoxLayout()
        
        # Grid para campos de entrada
        grid = QGridLayout()
        
        # Serviço
        self.label_service = QLabel("Service:")
        self.entry_service = QLineEdit()
        grid.addWidget(self.label_service, 0, 0)
        grid.addWidget(self.entry_service, 0, 1)
        
        # Comprimento da senha
        self.label_length = QLabel("Password Length:")
        self.entry_length = QLineEdit("12")
        grid.addWidget(self.label_length, 1, 0)
        grid.addWidget(self.entry_length, 1, 1)
        
        # Checkboxes para tipos de caracteres
        self.check_uppercase = QCheckBox("Include Uppercase Letters")
        self.check_uppercase.setChecked(True)
        self.check_lowercase = QCheckBox("Include Lowercase Letters")
        self.check_lowercase.setChecked(True)
        self.check_numbers = QCheckBox("Include Numbers")
        self.check_numbers.setChecked(True)
        self.check_symbols = QCheckBox("Include Symbols")
        self.check_symbols.setChecked(True)
        
        grid.addWidget(self.check_uppercase, 2, 0, 1, 2)
        grid.addWidget(self.check_lowercase, 3, 0, 1, 2)
        grid.addWidget(self.check_numbers, 4, 0, 1, 2)
        grid.addWidget(self.check_symbols, 5, 0, 1, 2)
        
        # Botão para gerar a senha
        self.btn_generate = QPushButton("Generate Password")
        self.btn_generate.clicked.connect(self.generate_password)
        grid.addWidget(self.btn_generate, 6, 0, 1, 2)
        
        # Campo para exibir a senha gerada
        self.entry_password = QLineEdit()
        self.entry_password.setReadOnly(True)
        grid.addWidget(self.entry_password, 7, 0, 1, 2)
        
        # Botão para salvar a senha
        self.btn_save = QPushButton("Save Password")
        self.btn_save.clicked.connect(self.save_password)
        grid.addWidget(self.btn_save, 8, 0, 1, 2)
        
        layout.addLayout(grid)
        
        # Tabela para exibir senhas armazenadas
        self.table = QTableWidget()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["Service", "Password"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.load_passwords()
        layout.addWidget(self.table)
        
        # Botões para excluir e atualizar senhas
        hbox_buttons = QHBoxLayout()
        self.btn_delete = QPushButton("Delete Password")
        self.btn_delete.clicked.connect(self.delete_password)
        self.btn_update = QPushButton("Update Password")
        self.btn_update.clicked.connect(self.update_password)
        hbox_buttons.addWidget(self.btn_delete)
        hbox_buttons.addWidget(self.btn_update)
        layout.addLayout(hbox_buttons)
        
        self.setLayout(layout)
    
    # Função para gerar a senha
    def generate_password(self):
        try:
            length = int(self.entry_length.text())
            if length < 4:
                raise ValueError("Password length must be at least 4 characters.")
            
            use_uppercase = self.check_uppercase.isChecked()
            use_lowercase = self.check_lowercase.isChecked()
            use_numbers = self.check_numbers.isChecked()
            use_symbols = self.check_symbols.isChecked()
            
            password = generate_password(length, use_uppercase, use_lowercase, use_numbers, use_symbols)
            self.entry_password.setText(password)
        
        except ValueError as ve:
            QMessageBox.critical(self, "Error", str(ve))
    
    # Função para salvar a senha
    def save_password(self):
        service = self.entry_service.text().strip()
        password = self.entry_password.text().strip()
        
        if service and password:
            existing_services = get_all_services()
            
            if service in existing_services:
                QMessageBox.warning(self, "Error", f"A password for {service} already exists.")
                return
            
            try:
                save_password(service, password)
                self.load_passwords()
                QMessageBox.information(self, "Success", f"Password for {service} saved successfully!")
            except ValueError as ve:
                QMessageBox.warning(self, "Error", str(ve))
        else:
            QMessageBox.warning(self, "Error", "Service and password cannot be empty!")
    
    # Função para carregar as senhas salvas na tabela
    def load_passwords(self):
        self.table.setRowCount(0)
        records = get_all_passwords()
        for row_num, row_data in enumerate(records):
            self.table.insertRow(row_num)
            self.table.setItem(row_num, 0, QTableWidgetItem(row_data[0]))
            self.table.setItem(row_num, 1, QTableWidgetItem(row_data[1]))
    
    # Função para excluir uma senha
    def delete_password(self):
        selected_row = self.table.currentRow()
        if selected_row >= 0:
            service = self.table.item(selected_row, 0).text()
            delete_password(service)
            self.load_passwords()
            QMessageBox.information(self, "Success", f"Password for {service} deleted successfully!")
        else:
            QMessageBox.warning(self, "Error", "Please select a service to delete.")
    
    # Função para atualizar a senha de um serviço
    def update_password(self):
        selected_row = self.table.currentRow()
        if selected_row >= 0:
            service = self.table.item(selected_row, 0).text()
            new_password = self.entry_password.text().strip()
            if new_password:
                update_password(service, new_password)
                self.load_passwords()
                QMessageBox.information(self, "Success", f"Password for {service} updated successfully!")
            else:
                QMessageBox.warning(self, "Error", "Please generate a new password to update.")
        else:
            QMessageBox.warning(self, "Error", "Please select a service to update.")
    
# Executando o aplicativo PyQt6
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordManager()
    window.show()
    sys.exit(app.exec())
