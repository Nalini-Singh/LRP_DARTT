
from fpdf import FPDF

def create_pdf_report(session_data, filename):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, 'Pentesting Report', ln=True, align='C')
    pdf.set_font('Arial', '', 12)
    for key, value in session_data.items():
        pdf.multi_cell(0, 10, f'{key}: {value}\n')
    pdf.output(filename)

def create_md_report(session_data, filename):
    content = "# Pentesting Report\n\n"
    for key, value in session_data.items():
        content += f"**{key}:** {value}\n\n"
    with open(filename, 'w') as md_file:
        md_file.write(content)
