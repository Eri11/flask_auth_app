SEGURIDAD INFORMÁTICA

BRYAN DAVID AGUILAR TALAMANTES 	 	 	 	 	 	1118150129 
JOSE FRANCISCO CENICEROS FONTES  	 	 	 	 	1118150113 
GILBERTO VIDAL CERVANTES HERNÁNDEZ 	 	 	 	 	1118150095 
ERIKA ELÍ DOMÍNGUEZ CARRILLO  	 	             	 	 	1118150132 


------
INSTRUCCIONES DE USO


Revisar version de ambiente virtual (venv)
virtualenv --version

Crear ambiente virtual
virtualenv auth

Una vez dentro del ambiente virtual:

	Instalar dependencias
		pip install -r requirements.txt

	Variables
		set FLASK_APP=project
		set FLASK_DEBUG=1

	Correr Flask
		run flask


-----

***Abrir otra terminal en VS Code, parar la primera (flask) sin cerrarla**
Escribir en terminal
	Python 
	
	from project import db, create_app, models
	
	db.create_all(app=create_app()) # pass the create_app result so Flask-SQLAlchemy gets the configuration.

Volver a correr flask
	
