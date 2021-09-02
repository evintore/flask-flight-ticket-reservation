
from flask import Flask, render_template, redirect, url_for, flash
import datetime
from sqlalchemy.sql import table, column, select
from flask_babelex import Babel
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField,SubmitField,IntegerField,DateField,SelectField
from wtforms.validators import InputRequired, Email, Length
from flask_login import login_required, LoginManager, UserMixin, login_user, logout_user, current_user
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import MetaData
#Kütüphaneler ve uygulamalar için gerekli config ayarları
app = Flask(__name__)
app.config['SECRET_KEY']='secreteyvol3'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///webdatabase.db'
Bootstrap(app)
db=SQLAlchemy(app)
login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'

 # Yükleme
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model): #UserMixin ekleme
	#Kullanıcı kimlik bilgileri doğrulama
	id=db.Column(db.Integer,autoincrement=True, primary_key=True)
	username=db.Column(db.String(20), unique=True)
	email=db.Column(db.String(50),unique=True)
	password=db.Column(db.String(100))
	#Role ile ilişkiyi UserRples üzerinden tanımlama
	roles = db.relationship('Role', secondary='user_roles') 

	# Role veri modelini tanımlama
class Role(db.Model):
	id=db.Column(db.Integer(),primary_key=True)
	name=db.Column(db.String(),unique=True)

	# Uçuş tanımlama
class Flight(db.Model):
	id=db.Column(db.Integer(), primary_key=True)
	route=db.Column(db.String(60),nullable=False)
	type=db.Column(db.String(20),nullable=False)
	seat=db.Column(db.Integer(),nullable=False)
	date=db.Column(db.String(50))
	cost=db.Column(db.Integer,nullable=False)

	# Fatura tanımlama
class Bill(db.Model):
	id=db.Column(db.Integer(),primary_key=True)
	rota=db.Column(db.String(60),db.ForeignKey('flight.route'),nullable=False)
	db.relationship('flight')
	date=db.Column(db.String(50),db.ForeignKey('flight.date'),nullable=False)
	db.relationship('flight')
	fiyat=db.Column(db.Integer,db.ForeignKey('flight.cost'),nullable=False)
	db.relationship('flight')


	# Bilet tanımlama
class Ticket(db.Model):
	id=db.Column(db.Integer(),primary_key=True)
	date=db.Column(db.DateTime,nullable=False)
	flightroute=db.Column(db.String(60),nullable=False)
	seattype=db.Column(db.String(50),nullable=False)
	ticket_id=db.Column(db.Integer,db.ForeignKey('flight.id'))
	db.relationship('flight')
	ticket_cost=db.Column(db.Integer,db.ForeignKey('flight.cost'))
	db.relationship('flight')

    # UserRoles ilişkilendirme tablosunu tanımlama
class UserRoles(db.Model):
	id=db.Column(db.Integer(),primary_key=True)
	user_id=db.Column(db.Integer(),db.ForeignKey('user.id', ondelete='CASCADE'))
	role_id=db.Column(db.Integer(),db.ForeignKey('role.id',ondelete='CASCADE'))
	
      
class Sepet:
	urunler={}
        

	db.create_all()


	# Giriş formu bilgileri tanımlama
class LoginForm(FlaskForm):
	username=StringField('username', validators=[InputRequired(),Length(min=4, max=20)])
	password=PasswordField('password', validators=[InputRequired(), Length(min=5, max=20)])

	# Kayıt formu bilgileri tanımlama
class RegisterForm(FlaskForm):
	username=StringField('username', validators=[InputRequired(),Length(min=4, max=20)])
	password=PasswordField('password', validators=[InputRequired(), Length(min=5, max=20)])
	email=StringField('email', validators=[InputRequired(), Email(message='Geçersiz Email'),Length(min=5, max=20)])

	# Uçuş formu bilgileri tanımlama
class FlightForm(FlaskForm):
	type=StringField('Uçuş Tipi', validators=[InputRequired()])
	route=StringField('Rota', validators=[InputRequired()])
	seat=StringField('Koltuk Sayısı', validators=[InputRequired()])
	date=StringField('Tarih', validators=[InputRequired()])
	cost=StringField('Fiyat', validators=[InputRequired()])

	# Uçuş listeleme, tarih, maliyet ve uçuş tibi tanımlama
class FlightList(object):
	def __iter__(self):
		flights=Flight.query.all()
		choices=[(flight.id,flight.route)for flight in flights]
		for choice in choices:
			yield choice

class FlightDate(object):
	def __iter__(self):
		flights=Flight.query.all()
		choices=[(flight.id,flight.date)for flight in flights]
		for choice in choices:
			yield choice

class FlightCost(object):
	def __iter__(self):
		flights=Flight.query.all()
		choices=[(flight.id,flight.cost)for flight in flights]
		for choice in choices:
			yield choice

class FlightType(object):
	def __iter__(self):
		tickets=Ticket.query.all()
		choices=[(ticket.id,ticket.seattype)for ticket in tickets]
		for choice in choices:
			yield choice


			# Bilet, sepet ve bilet liste formları tanımlama
class TicketForm(FlaskForm):
	routes=SelectField('Rota Seçiniz: ', coerce=int, choices=FlightList())
	date=DateField('Tarih Seçiniz', format="%m/%d/%Y",validators=[InputRequired()])
	type=StringField('Bilet tipinizi seçiniz:')


class SepetForm(FlaskForm):
	routes=SelectField('Seçtiğiniz Rota', coerce=int, choices=FlightList())
	date=SelectField('Tarih', coerce=int, choices=FlightDate())
	cost=SelectField('Fiyat', coerce=int, choices=FlightCost())


class TicketlistForm(FlaskForm):
	routes=SelectField('Seçtiğiniz Rota', coerce=int, choices=FlightList())
	date=SelectField('Tarih', coerce=int, choices=FlightDate())
	cost=SelectField('Fiyat', coerce=int, choices=FlightCost())
	seattype=SelectField('Tür', coerce=int, choices=FlightType())


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
	form=LoginForm()

	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user:
			if check_password_hash(user.password,form.password.data):
				login_user(user)
				return redirect(url_for('dashboard'))

		flash('Giriş Bilgileri Yanlış')
		return redirect(url_for('login'))
		

	return render_template('login.html',form=form)

@app.route('/signup', methods=['GET','POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
       	hashed_password= generate_password_hash(form.password.data, method='sha256')
        new_user=User(username=form.username.data, email=form.email.data,password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Kullanıcı başarıyla kaydedildi.')
        return redirect(url_for('index'))
    

    return render_template('signup.html',form=form)

@app.route('/addflight', methods=['GET','POST'])
def addflight():
	form=FlightForm()
	if form.validate_on_submit():
		new_flight=Flight(route=form.route.data, type=form.type.data, seat=form.seat.data, date=form.date.data,cost=form.cost.data)
		db.session.add(new_flight)
		db.session.commit()

		flash("Uçuş Eklendi.")
		return redirect(url_for('index'))
	return render_template('addflight.html',form=form)

@app.route('/res', methods=['GET','POST'])
@login_required # Use of @login_required decorator
def res():
	form=TicketForm()
	if form.validate_on_submit():
		flight=Flight.query.filter_by(id=form.routes.data).first()
		new_res=Ticket(flightroute=flight.route,ticket_id=current_user.id, date=form.date.data, seattype=form.type.data)
		db.session.add(new_res)
		db.session.commit()

		flash("Sepete Eklendi.")
		return redirect(url_for('dashboard'))
	return render_template('res.html',form=form)

@app.route("/logout")
def logout():
	logout_user()
	flash("Başarı ile çıkış yaptınız.")
	return redirect(url_for('index'))


@app.route('/dashboard')
@login_required # Use of @login_required decorator
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin')
@login_required
def admin():
	if not current_user.is_authenticated:
		flash('Admin olarak giriş yapınız.')
		return redirect(url_for('login'))

	if current_user.username!='admin':
		flash('Admin olarak giriş yapınız.')
		return redirect(url_for('login'))
	return render_template('admin.html')


@app.route('/sepet', methods=['GET','POST'])
@login_required # Use of @login_required decorator
def sepet():
	form=SepetForm()
	if form.validate_on_submit():
		flight=Flight.query.filter_by(id=form.routes.data).first()
		new_bill=Bill(rota=form.routes.data,date=form.date.data,fiyat=form.cost.data)
		db.session.add(new_bill)
		db.session.commit()
		flash('Satın Alma Gerçekleştirildi')
		return redirect(url_for('index'))


	return render_template('sepet.html',form=form)


@app.route('/ticketlist', methods=['GET', 'POST'])
@login_required # Use of @login_required decorator
def ticketlist():
	form=TicketlistForm()



	return render_template('/ticketlist.html', form=form)


	#web sunucusunu başlatma
if __name__ == '__main__':
    app.run(debug=True)