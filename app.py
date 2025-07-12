from flask import Flask, request, render_template, redirect, url_for
import csv
import re
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def load_csv_data(csv_filename):
    with open(csv_filename, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        return list(reader)

def detect_sql_injection_patterns():
    return [
        r"(?i)(?:union.*select|select.*from|insert.*into|update.*set|delete.*from|drop.*table)",
        r"(?i)(?:'\s*or\s*'|\"\s*or\s*\"|\bor\b\s*\d+\s*=\s*\d+)",
        r"(?i)(?:'\s*--|\"\s*--|;\s*--|#|/\*)",
        r"(?i)(?:\bwaitfor\s+delay\b|\bsleep\b)"
    ]

def find_sql_injection_attempts(data, sql_patterns):
    attacker_ip = None
    sql_attempts = []
    formatted_symbol_count = 0
    
    for row in data:
        info = row.get('Info', '')
        
        if any(re.search(pattern, info) for pattern in sql_patterns):
            if not attacker_ip:
                attacker_ip = row.get('Source')
            
            if row.get('Source') == attacker_ip:
                sql_attempts.append((row.get('Time'), info))
                if ':' in info:
                    formatted_symbol_count += 1
    
    return attacker_ip, sql_attempts, formatted_symbol_count

def process_file(filepath):
    data = load_csv_data(filepath)
    sql_patterns = detect_sql_injection_patterns()
    attacker_ip, sql_attempts, formatted_symbol_count = find_sql_injection_attempts(data, sql_patterns)
    sql_attempts.sort()
    
    first_payload = sql_attempts[0][1] if sql_attempts else "NULL"
    last_payload = sql_attempts[-1][1] if sql_attempts else "NULL"

    results = {
        'attacker_ip': attacker_ip if attacker_ip else 'NULL',
        'attempt_count': len(sql_attempts),
        'first_payload': first_payload,
        'last_payload': last_payload,
        'formatted_symbol_count': formatted_symbol_count
    }
    return results

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        
        if file:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filepath)
            results = process_file(filepath)
            os.remove(filepath)  # Optional: remove file after processing
            return render_template('result.html', results=results)
    
    return render_template('upload.html')

if __name__ == '__main__':
    app.run(debug=True)
