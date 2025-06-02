from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
import json
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
DB_FILE = 'database.json'

# Ensure upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Load or create JSON database
# Database functions
def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, 'r') as f:
            return json.load(f)
    return {
        'controls': {},
        'documents': [],
        'audits': {}
    }

def save_db(db):
    with open(DB_FILE, 'w') as f:
        json.dump(db, f, indent=4)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# User credentials (hardcoded as requested)
USERS = {
    'user': {'password': 'user', 'role': 'user'},
    'auditor': {'password': 'auditor', 'role': 'auditor'}
}

# Definición completa de controles ISO 27001
ISO_CONTROLS = {
    "A.5": {
        "title": "Políticas de seguridad de la información",
        "controls": {
            "A.5.1": {
                "title": "Directrices de gestión de la seguridad de la información",
                "subcontrols": {
                    "A.5.1.1": "Políticas para la seguridad de la información",
                    "A.5.1.2": "Revisión de las políticas para la seguridad de la información"
                }
            }
        }
    },
    "A.6": {
        "title": "Organización de la seguridad de la información",
        "controls": {
            "A.6.1": {
                "title": "Organización interna",
                "subcontrols": {
                    "A.6.1.1": "Roles y responsabilidades de seguridad de la información",
                    "A.6.1.2": "Segregación de funciones",
                    "A.6.1.3": "Contacto con autoridades",
                    "A.6.1.4": "Contacto con grupos de interés especial",
                    "A.6.1.5": "Seguridad de la información en la gestión de proyectos"
                }
            },
            "A.6.2": {
                "title": "Dispositivos móviles y teletrabajo",
                "subcontrols": {
                    "A.6.2.1": "Política de dispositivos móviles",
                    "A.6.2.2": "Teletrabajo"
                }
            }
        }
    },
    "A.7": {
        "title": "Seguridad ligada a los recursos humanos",
        "controls": {
            "A.7.1": {
                "title": "Antes de la contratación",
                "subcontrols": {
                    "A.7.1.1": "Investigación de antecedentes",
                    "A.7.1.2": "Términos y condiciones de contratación"
                }
            },
            "A.7.2": {
                "title": "Durante la contratación",
                "subcontrols": {
                    "A.7.2.1": "Responsabilidades de gestión",
                    "A.7.2.2": "Concienciación, educación y capacitación en seguridad de la información",
                    "A.7.2.3": "Proceso disciplinario"
                }
            },
            "A.7.3": {
                "title": "Cese o cambio de puesto de trabajo",
                "subcontrols": {
                    "A.7.3.1": "Responsabilidades ante el cese o cambio"
                }
            }
        }
    },
    "A.8": {
        "title": "Gestión de activos",
        "controls": {
            "A.8.1": {
                "title": "Responsabilidad sobre los activos",
                "subcontrols": {
                    "A.8.1.1": "Inventario de activos",
                    "A.8.1.2": "Propiedad de los activos",
                    "A.8.1.3": "Uso aceptable de los activos",
                    "A.8.1.4": "Devolución de activos"
                }
            },
            "A.8.2": {
                "title": "Clasificación de la información",
                "subcontrols": {
                    "A.8.2.1": "Clasificación de la información",
                    "A.8.2.2": "Etiquetado de la información",
                    "A.8.2.3": "Manipulación de la información"
                }
            },
            "A.8.3": {
                "title": "Manipulación de soportes",
                "subcontrols": {
                    "A.8.3.1": "Gestión de soportes extraíbles",
                    "A.8.3.2": "Eliminación de soportes",
                    "A.8.3.3": "Soportes físicos en tránsito"
                }
            }
        }
    },
    "A.9": {
        "title": "Control de acceso",
        "controls": {
            "A.9.1": {
                "title": "Requisitos de negocio para el control de acceso",
                "subcontrols": {
                    "A.9.1.1": "Política de control de acceso",
                    "A.9.1.2": "Acceso a las redes y a los servicios de red"
                }
            },
            "A.9.2": {
                "title": "Gestión de acceso de usuario",
                "subcontrols": {
                    "A.9.2.1": "Registro y baja de usuario",
                    "A.9.2.2": "Provisión de acceso de usuario",
                    "A.9.2.3": "Gestión de privilegios de acceso",
                    "A.9.2.4": "Gestión de la información secreta de autenticación de los usuarios",
                    "A.9.2.5": "Revisión de los derechos de acceso de usuario",
                    "A.9.2.6": "Retirada o reasignación de los derechos de acceso"
                }
            },
            "A.9.3": {
                "title": "Responsabilidades del usuario",
                "subcontrols": {
                    "A.9.3.1": "Uso de la información secreta de autenticación"
                }
            },
            "A.9.4": {
                "title": "Control de acceso a sistemas y aplicaciones",
                "subcontrols": {
                    "A.9.4.1": "Restricción del acceso a la información",
                    "A.9.4.2": "Procedimientos seguros de inicio de sesión",
                    "A.9.4.3": "Sistema de gestión de contraseñas",
                    "A.9.4.4": "Uso de utilidades con privilegios del sistema",
                    "A.9.4.5": "Control de acceso al código fuente de los programas"
                }
            }
        }
    },
    "A.10": {
        "title": "Criptografía",
        "controls": {
            "A.10.1": {
                "title": "Controles criptográficos",
                "subcontrols": {
                    "A.10.1.1": "Política de uso de los controles criptográficos",
                    "A.10.1.2": "Gestión de claves"
                }
            }
        }
    },
    "A.11": {
        "title": "Seguridad física y del entorno",
        "controls": {
            "A.11.1": {
                "title": "Áreas seguras",
                "subcontrols": {
                    "A.11.1.1": "Perímetro de seguridad física",
                    "A.11.1.2": "Controles físicos de entrada",
                    "A.11.1.3": "Seguridad de oficinas, despachos y recursos",
                    "A.11.1.4": "Protección contra las amenazas externas y ambientales",
                    "A.11.1.5": "El trabajo en áreas seguras",
                    "A.11.1.6": "Áreas de carga y descarga"
                }
            },
            "A.11.2": {
                "title": "Seguridad de los equipos",
                "subcontrols": {
                    "A.11.2.1": "Emplazamiento y protección de equipos",
                    "A.11.2.2": "Instalaciones de suministro",
                    "A.11.2.3": "Seguridad del cableado",
                    "A.11.2.4": "Mantenimiento de los equipos",
                    "A.11.2.5": "Retirada de materiales propiedad de la empresa",
                    "A.11.2.6": "Seguridad de los equipos fuera de las instalaciones",
                    "A.11.2.7": "Reutilización o eliminación segura de equipos",
                    "A.11.2.8": "Equipo de usuario desatendido",
                    "A.11.2.9": "Política de puesto de trabajo despejado y pantalla limpia"
                }
            }
        }
    },
    "A.12": {
        "title": "Seguridad de las operaciones",
        "controls": {
            "A.12.1": {
                "title": "Procedimientos y responsabilidades operacionales",
                "subcontrols": {
                    "A.12.1.1": "Documentación de procedimientos operacionales",
                    "A.12.1.2": "Gestión de cambios",
                    "A.12.1.3": "Gestión de capacidades",
                    "A.12.1.4": "Separación de los recursos de desarrollo, prueba y operación"
                }
            },
            "A.12.2": {
                "title": "Protección contra el software malicioso (malware)",
                "subcontrols": {
                    "A.12.2.1": "Controles contra el código malicioso"
                }
            },
            "A.12.3": {
                "title": "Copias de seguridad",
                "subcontrols": {
                    "A.12.3.1": "Copias de seguridad de la información"
                }
            },
            "A.12.4": {
                "title": "Registros y supervisión",
                "subcontrols": {
                    "A.12.4.1": "Registro de eventos",
                    "A.12.4.2": "Protección de la información del registro",
                    "A.12.4.3": "Registros de administración y operación",
                    "A.12.4.4": "Sincronización del reloj"
                }
            },
            "A.12.5": {
                "title": "Control del software en explotación",
                "subcontrols": {
                    "A.12.5.1": "Instalación del software en explotación"
                }
            },
            "A.12.6": {
                "title": "Gestión de la vulnerabilidad técnica",
                "subcontrols": {
                    "A.12.6.1": "Gestión de las vulnerabilidades técnicas",
                    "A.12.6.2": "Restricciones en la instalación de software"
                }
            },
            "A.12.7": {
                "title": "Consideraciones sobre la auditoría de sistemas de información",
                "subcontrols": {
                    "A.12.7.1": "Controles de auditoría de sistemas de información"
                }
            }
        }
    },
    "A.13": {
        "title": "Seguridad de las comunicaciones",
        "controls": {
            "A.13.1": {
                "title": "Gestión de la seguridad de las redes",
                "subcontrols": {
                    "A.13.1.1": "Controles de red",
                    "A.13.1.2": "Seguridad de los servicios de red",
                    "A.13.1.3": "Segregación en redes"
                }
            },
            "A.13.2": {
                "title": "Intercambio de información",
                "subcontrols": {
                    "A.13.2.1": "Políticas y procedimientos de intercambio de información",
                    "A.13.2.2": "Acuerdos de intercambio de información",
                    "A.13.2.3": "Mensajería electrónica",
                    "A.13.2.4": "Acuerdos de confidencialidad o no revelación"
                }
            }
        }
    },
    "A.14": {
        "title": "Adquisición, desarrollo y mantenimiento de los sistemas de información",
        "controls": {
            "A.14.1": {
                "title": "Requisitos de seguridad de los sistemas de información",
                "subcontrols": {
                    "A.14.1.1": "Análisis de requisitos y especificaciones de seguridad de la información",
                    "A.14.1.2": "Asegurar los servicios de aplicaciones en redes públicas",
                    "A.14.1.3": "Protección de las transacciones de servicios de aplicaciones"
                }
            },
            "A.14.2": {
                "title": "Seguridad en el desarrollo y en los procesos de soporte",
                "subcontrols": {
                    "A.14.2.1": "Política de desarrollo seguro",
                    "A.14.2.2": "Procedimientos de control de cambios en sistemas",
                    "A.14.2.3": "Revisión técnica de las aplicaciones tras efectuar cambios en el sistema operativo",
                    "A.14.2.4": "Restricciones a los cambios en los paquetes de software",
                    "A.14.2.5": "Principios de ingeniería de sistemas seguros",
                    "A.14.2.6": "Entorno de desarrollo seguro",
                    "A.14.2.7": "Externalización del desarrollo de software",
                    "A.14.2.8": "Pruebas funcionales de seguridad de sistemas",
                    "A.14.2.9": "Pruebas de aceptación de sistemas"
                }
            },
            "A.14.3": {
                "title": "Datos de prueba",
                "subcontrols": {
                    "A.14.3.1": "Protección de los datos de prueba"
                }
            }
        }
    },
    "A.15": {
        "title": "Relación con proveedores",
        "controls": {
            "A.15.1": {
                "title": "Seguridad en las relaciones con proveedores",
                "subcontrols": {
                    "A.15.1.1": "Política de seguridad de la información en las relaciones con los proveedores",
                    "A.15.1.2": "Requisitos de seguridad en contratos con terceros",
                    "A.15.1.3": "Cadena de suministro de tecnología de la información y de las comunicaciones"
                }
            },
            "A.15.2": {
                "title": "Gestión de la prestación de servicios por proveedores",
                "subcontrols": {
                    "A.15.2.1": "Control y revisión de la provisión de servicios del proveedor",
                    "A.15.2.2": "Gestión de cambios en la provisión del servicio del proveedor"
                }
            }
        }
    },
    "A.16": {
        "title": "Gestión de incidentes de seguridad de la información",
        "controls": {
            "A.16.1": {
                "title": "Gestión de incidentes de seguridad de la información y mejoras",
                "subcontrols": {
                    "A.16.1.1": "Responsabilidades y procedimientos",
                    "A.16.1.2": "Notificación de los eventos de seguridad de la información",
                    "A.16.1.3": "Notificación de puntos débiles de la seguridad",
                    "A.16.1.4": "Evaluación y decisión sobre los eventos de seguridad de información",
                    "A.16.1.5": "Respuesta a incidentes de seguridad de la información",
                    "A.16.1.6": "Aprendizaje de los incidentes de seguridad de la información",
                    "A.16.1.7": "Recopilación de evidencias"
                }
            }
        }
    },
    "A.17": {
        "title": "Aspectos de seguridad de la información para la gestión de la continuidad de negocio",
        "controls": {
            "A.17.1": {
                "title": "Continuidad de la seguridad de la información",
                "subcontrols": {
                    "A.17.1.1": "Planificación de la continuidad de la seguridad de la información",
                    "A.17.1.2": "Implementación de la continuidad de la seguridad de la información",
                    "A.17.1.3": "Verificación, revisión y evaluación de la continuidad de la seguridad de la información"
                }
            },
            "A.17.2": {
                "title": "Redundancias",
                "subcontrols": {
                    "A.17.2.1": "Disponibilidad de los recursos de tratamiento de la información"
                }
            }
        }
    },
    "A.18": {
        "title": "Cumplimiento",
        "controls": {
            "A.18.1": {
                "title": "Cumplimiento de los requisitos legales y contractuales",
                "subcontrols": {
                    "A.18.1.1": "Identificación de la legislación aplicable y de los requisitos contractuales",
                    "A.18.1.2": "Derechos de propiedad intelectual (DPI)",
                    "A.18.1.3": "Protección de los registros de la organización",
                    "A.18.1.4": "Protección y privacidad de la información de carácter personal",
                    "A.18.1.5": "Regulación de los controles criptográficos"
                }
            },
            "A.18.2": {
                "title": "Revisiones de la seguridad de la información",
                "subcontrols": {
                    "A.18.2.1": "Revisión independiente de la seguridad de la información",
                    "A.18.2.2": "Cumplimiento de las políticas y normas de seguridad",
                    "A.18.2.3": "Comprobación del cumplimiento técnico"
                }
            }
        }
    }
}

# User credentials (hardcoded as requested)
USERS = {
    'user': {'password': 'user', 'role': 'user'},
    'auditor': {'password': 'auditor', 'role': 'auditor'}
}

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', role=session.get('role'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in USERS and USERS[username]['password'] == password:
            session['username'] = username
            session['role'] = USERS[username]['role']
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session or session['role'] != 'user':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            db = load_db()
            db['documents'].append(filename)
            save_db(db)
            flash('File uploaded successfully')
            return redirect(url_for('upload'))
    db = load_db()
    return render_template('upload.html', documents=db['documents'])

@app.route('/map_controls', methods=['GET', 'POST'])
def map_controls():
    if 'username' not in session or session['role'] != 'user':
        return redirect(url_for('login'))
    
    db = load_db()
    if request.method == 'POST':
        control = request.form['control']
        documents = request.form.getlist('documents')
        
        # Obtener el título del control si existe
        control_title = None
        for section in ISO_CONTROLS.values():
            for ctrl in section['controls'].values():
                if control in ctrl.get('subcontrols', {}):
                    control_title = ctrl['subcontrols'][control]
                    break
            if control_title:
                break
        
        db['controls'][control] = {
            'title': control_title,
            'documents': documents,
            'status': 'pending',
            'score': 0,
            'comment': ''
        }
        save_db(db)
        flash('Control mapping saved')
    return render_template('map_controls.html', 
                         documents=db['documents'], 
                         controls=db['controls'],
                         iso_controls=ISO_CONTROLS)

@app.route('/audit', methods=['GET', 'POST'])
def audit():
    if 'username' not in session or session['role'] != 'auditor':
        return redirect(url_for('login'))
    
    db = load_db()
    if request.method == 'POST':
        control = request.form['control']
        score = int(request.form['score'])
        comment = request.form['comment']
        
        status = 'Incumple'
        if score == 100:
            status = 'Cumple'
        elif 67 <= score <= 99:
            status = 'Observación'
        elif 34 <= score <= 66:
            status = 'No conformidad menor'
        elif 1 <= score <= 33:
            status = 'No conformidad mayor'
        
        db['controls'][control].update({
            'status': status,
            'score': score,
            'comment': comment
        })
        save_db(db)
        flash('Audit evaluation saved')
    return render_template('audit.html', controls=db['controls'])

if __name__ == '__main__':
    app.run(debug=True)