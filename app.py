import flask as fl
import sys
import json
from flask_sqlalchemy import SQLAlchemy
import os
import bcrypt
import time
import uuid
from authlib.integrations.flask_client import OAuth
from flask_session import Session
from datetime import datetime, timedelta
from datetime import date
from dotenv import load_dotenv
from sqlalchemy import text
from werkzeug.utils import secure_filename
from fpdf import FPDF
import io

load_dotenv()

app = fl.Flask(__name__)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

facebook = oauth.register(
    name='facebook',
    client_id=os.getenv("FACEBOOK_CLIENT_ID"),
    client_secret=os.getenv("FACEBOOK_CLIENT_SECRET"),
    access_token_url='https://graph.facebook.com/oauth/access_token',
    access_token_params=None,
    authorize_url='https://www.facebook.com/dialog/oauth',
    authorize_params=None,
    api_base_url='https://graph.facebook.com/',
    client_kwargs={'scope': 'email public_profile'},
)

app.config["SECRET_KEY"] = "o_cheie_secreta_foarte_complicata"
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False

Session(app)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "mssql+pyodbc:///?odbc_connect=DRIVER={ODBC+Driver+17+for+SQL+Server};SERVER=VASIVBM\\SQLEXPRESS;DATABASE=CabinetVeterinar;Trusted_Connection=yes;"
)

db = SQLAlchemy(app)

# =======================================================
# ZONA 1: AUTENTIFICARE & CONT UTILIZATOR
# =======================================================


@app.route("/login", methods=["GET", "POST"])
def show_login_page():
    if fl.request.method == "POST":
        email = fl.request.form.get("email")
        password = fl.request.form.get("password")
        remember_me = fl.request.form.get("remember_me")

        if not email or not password:
            fl.flash("Introduceți toate câmpurile.", "danger")
            return fl.redirect(fl.url_for("login_page"))

        try:
            sql_select = "SELECT Parola, Username, Id_user FROM USER_ACCOUNT WHERE Email = :email"
            user_record = db.session.execute(
                text(sql_select), {"email": email}
            ).fetchone()

            if not user_record:
                fl.flash("Email sau parolă incorectă.", "danger")
                return fl.redirect(fl.url_for("login_page"))

            stored_hashed_password = user_record[0]
            username = user_record[1]
            user_id = user_record[2]

            if not bcrypt.checkpw(
                password.encode("utf-8"), stored_hashed_password.encode("utf-8")
            ):
                fl.flash("Email sau parolă incorectă.", "danger")
                return fl.redirect(fl.url_for("login_page"))

            fl.session["logged_in"] = True
            fl.session["user_id"] = user_id
            fl.session["username"] = username
            fl.session["email"] = email

            response = fl.make_response(fl.redirect(fl.url_for("index")))

            if remember_me:
                expires_date = datetime.now() + timedelta(days=30)
                response.set_cookie(
                    "remember_email", email, expires=expires_date, httponly=True
                )
            else:
                response.delete_cookie("remember_email")

            return response

        except Exception as e:
            print(f"Eroare la autentificare: {e}")
            fl.flash("Eroare internă a serverului.", "danger")
            return fl.redirect(fl.url_for("login_page"))

    else:
        remembered_email = fl.request.cookies.get("remember_email")
        return fl.render_template("login.html", remembered_email=remembered_email)


@app.route("/register", methods=["GET", "POST"])
def show_register_page():
    if fl.request.method == "POST":
        username = fl.request.form.get("username")
        email = fl.request.form.get("email")
        password = fl.request.form.get("password")
        retypepassword = fl.request.form.get("retype_password")

        if not username or not email or not password or password != retypepassword:
            return "ERROR: Completează toate câmpurile și verifică parolele.", 400

        if len(password) < 8:
            return "ERROR: Parola trebuie să aibă minim 8 caractere.", 400

        try:
            sql_check = "SELECT Username FROM USER_ACCOUNT WHERE Username = :user OR Email = :email"
            rezultat = db.session.execute(
                text(sql_check), {"user": username, "email": email}
            ).fetchone()

            if rezultat:
                return "ERROR: Userul sau emailul există deja.", 409

            password_bytes = password.encode("utf-8")
            hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode(
                "utf-8"
            )

            sql_insert = "INSERT INTO USER_ACCOUNT (Username, Email, Parola) VALUES (:user, :email, :password)"
            db.session.execute(
                text(sql_insert),
                {"user": username, "email": email, "password": hashed_password},
            )
            db.session.commit()

            return fl.redirect(fl.url_for("show_login_page"))

        except Exception as ex:
            print(f"Eroare BD: {ex}", file=sys.stderr)
            return f"Eroare de server: {ex}", 500

    else:
        return fl.render_template("register.html")


@app.route("/login/google")
def google_login():
    redirect_uri = fl.url_for("google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route("/login/google/callback")
def google_callback():
    try:
        token = google.authorize_access_token()
        user_info = token.get("userinfo")

        email = user_info.get("email")
        nume = user_info.get("name")
        picture = user_info.get("picture")

        sql_select = "SELECT * FROM USER_ACCOUNT WHERE Email = :email"
        existing_user = db.session.execute(
            text(sql_select), {"email": email}
        ).fetchone()

        user_id = None
        user_username = None
        user_poza = None

        if existing_user:
            user_id = existing_user[0]
            user_username = existing_user[1]
            db_pic = existing_user[4]
            user_poza = db_pic if db_pic else picture
        else:
            random_password = str(uuid.uuid4())
            hashed_password = bcrypt.hashpw(
                random_password.encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")

            sql_insert = """
                INSERT INTO USER_ACCOUNT (Email, Username, Parola, Profile_Pic) 
                VALUES (:email, :username, :parola, :poza)
            """
            db.session.execute(
                text(sql_insert),
                {
                    "email": email,
                    "username": nume,
                    "parola": hashed_password,
                    "poza": picture,
                },
            )
            db.session.commit()

            new_user = db.session.execute(text(sql_select), {"email": email}).fetchone()
            user_id = new_user[0]
            user_username = nume
            user_poza = picture

        fl.session["logged_in"] = True
        fl.session["user_id"] = user_id
        fl.session["username"] = user_username
        fl.session["email"] = email
        fl.session["profile_pic"] = user_poza

        return fl.redirect(fl.url_for("index"))

    except Exception as e:
        print(f"Eroare Google Login: {e}")
        return "Eroare la autentificarea cu Google.", 500
    

@app.route('/login/facebook')
def login_facebook():
    redirect_uri = fl.url_for('facebook_auth', _external=True)
    return facebook.authorize_redirect(redirect_uri)

@app.route('/login/facebook/callback')
def facebook_auth():
    try:
        token = facebook.authorize_access_token()
        
        resp = facebook.get('me?fields=id,name,email,picture.type(large)')
        user_info = resp.json()
        
        email = user_info.get('email')
        fl.session['user'] = user_info
        
        return fl.redirect('/')
    except Exception as e:
        return f"Eroare la logare: {e}"


@app.route("/forgot-password")
def show_forgot_password_page():
    return fl.render_template("forgot-password.html")


@app.route("/forgot-passwordpage", methods=["POST"])
def forgot_password():
    email = fl.request.form.get("email")

    if not email:
        return ("ERROR: Te rog completează adresa de email.", 400)

    try:
        sql_check_email = "SELECT Email FROM USER_ACCOUNT WHERE Email = :email"
        user_record = db.session.execute(
            text(sql_check_email), {"email": email}
        ).fetchone()

        if user_record:
            fl.session["reset_email"] = email
            return fl.redirect(fl.url_for("show_retype_password_page"))
        else:
            return ("ERROR: Email-ul nu a fost găsit în baza de date.", 409)

    except Exception as ex:
        print(f"Eroare BD: {ex}")
        return "Eroare server.", 500


@app.route("/retype-password")
def show_retype_password_page():
    return fl.render_template("retype_password.html")


@app.route("/retype-password", methods=["POST"])
def retype_password():
    email_to_update = fl.session.get("reset_email")
    password = fl.request.form.get("password")
    retype_password = fl.request.form.get("retype_password")

    if not email_to_update:
        return ("ERROR: Sesiunea a expirat.", 403)

    if not password or not retype_password or password != retype_password:
        return ("ERROR: Parolele nu se potrivesc.", 400)

    try:
        password_bytes = password.encode("utf-8")
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

        sql_update = "UPDATE USER_ACCOUNT SET Parola = :password WHERE Email = :email"
        db.session.execute(
            text(sql_update), {"password": hashed_password, "email": email_to_update}
        )
        db.session.commit()

        fl.session.pop("reset_email", None)
        return fl.redirect(fl.url_for("show_login_page"))

    except Exception as ex:
        db.session.rollback()
        print(f"Eroare resetare: {ex}")
        return "Eroare server.", 500


@app.route("/logout")
def logout():
    fl.session.clear()
    return fl.redirect(fl.url_for("show_login_page"))


# =======================================================
# ZONA 2: DASHBOARD & NAVIGARE PRINCIPALĂ
# =======================================================


@app.route("/")
def index():
    if "logged_in" not in fl.session or not fl.session["logged_in"]:
        return fl.redirect(fl.url_for("show_login_page"))

    card_animale = (
        db.session.execute(text("SELECT COUNT(Id_Animal) FROM ANIMAL")).scalar() or 0
    )
    card_stapani = (
        db.session.execute(text("SELECT COUNT(Id_stapan) FROM STAPAN")).scalar() or 0
    )
    card_consultatii = (
        db.session.execute(text("SELECT COUNT(Id_fisa) FROM FISA_MEDICALA")).scalar()
        or 0
    )

    sql_luna = """
        SELECT COUNT(Id_fisa)
        FROM FISA_MEDICALA
        WHERE MONTH(Data_vizite) = MONTH(GETDATE()) AND YEAR(Data_vizite) = YEAR(GETDATE())
    """
    try:
        card_activitate_luna = db.session.execute(text(sql_luna)).scalar() or 0
    except:
        card_activitate_luna = 0

    sql_pie = "SELECT Specie, COUNT(Id_animal) FROM ANIMAL GROUP BY Specie"
    rezultat_pie = db.session.execute(text(sql_pie)).fetchall()

    lista_etichete = [row[0] for row in rezultat_pie]
    lista_valori = [row[1] for row in rezultat_pie]

    pie_labels_json = json.dumps(lista_etichete)
    pie_values_json = json.dumps(lista_valori)

    user_data = {
        "username": fl.session.get("username", "User"),
        "profile_picture_url": fl.session.get(
            "profile_pic", fl.url_for("static", filename="img/default_avatar.jpg")
        ),
    }

    return fl.render_template(
        "dashboard.html",
        user=user_data,
        nr_animale=card_animale,
        nr_stapani=card_stapani,
        nr_consultatii=card_consultatii,
        nr_activitate_luna=card_activitate_luna,
        pie_labels_json=pie_labels_json,
        pie_values_json=pie_values_json,
    )


@app.route("/search")
def search_animal():
    query = fl.request.args.get("q", "").strip()
    if not query:
        return fl.redirect(fl.url_for("show_animal_page"))

    sql_search = """
        SELECT A.Id_animal
        FROM ANIMAL A
        JOIN STAPAN S ON A.Id_stapan = S.Id_stapan
        WHERE A.Nume LIKE :q OR S.Nume LIKE :q OR S.Prenume LIKE :q
    """
    search_term = f"%{query}%"
    results = db.session.execute(text(sql_search), {"q": search_term}).fetchall()

    if len(results) == 1:
        return fl.redirect(fl.url_for("show_animal_page", id=results[0].Id_animal))
    elif len(results) > 1:
        fl.flash(f"Găsite {len(results)} rezultate. Afișăm primul.", "info")
        return fl.redirect(fl.url_for("show_animal_page", id=results[0].Id_animal))
    else:
        fl.flash("Niciun rezultat găsit.", "danger")
        return fl.redirect(fl.url_for("show_animal_page"))


@app.route("/profile", methods=["GET", "POST"])
def show_profile_page():
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))

    user_id = fl.session["user_id"]

    if fl.request.method == "POST":
        try:
            nume = fl.request.form.get("nume")
            prenume = fl.request.form.get("prenume")
            telefon = fl.request.form.get("telefon")
            adresa = fl.request.form.get("adresa")

            check_stapan = db.session.execute(
                text("SELECT Id_stapan FROM STAPAN WHERE Id_user = :uid"),
                {"uid": user_id},
            ).fetchone()

            if check_stapan:
                sql_update = "UPDATE STAPAN SET Nume=:n, Prenume=:p, Telefon=:t, Adresa=:a WHERE Id_user=:uid"
                db.session.execute(
                    text(sql_update),
                    {
                        "n": nume,
                        "p": prenume,
                        "t": telefon,
                        "a": adresa,
                        "uid": user_id,
                    },
                )
            else:
                sql_insert = "INSERT INTO STAPAN (Id_user, Nume, Prenume, Telefon, Adresa) VALUES (:uid, :n, :p, :t, :a)"
                db.session.execute(
                    text(sql_insert),
                    {
                        "uid": user_id,
                        "n": nume,
                        "p": prenume,
                        "t": telefon,
                        "a": adresa,
                    },
                )

            file = fl.request.files.get("file_poza")
            if file and file.filename:
                filename = secure_filename(file.filename)
                save_path = os.path.join(app.root_path, "static/img", filename)
                file.save(save_path)
                new_pic_url = fl.url_for("static", filename=f"img/{filename}")

                db.session.execute(
                    text(
                        "UPDATE USER_ACCOUNT SET Profile_Pic = :pic WHERE Id_user = :uid"
                    ),
                    {"pic": new_pic_url, "uid": user_id},
                )
                fl.session["profile_pic"] = new_pic_url

            db.session.commit()
            fl.flash("Profil actualizat!", "success")

        except Exception as e:
            db.session.rollback()
            fl.flash(f"Eroare: {e}", "danger")

    sql_user = (
        "SELECT Username, Email, Profile_Pic FROM USER_ACCOUNT WHERE Id_user = :uid"
    )
    user_res = db.session.execute(text(sql_user), {"uid": user_id}).fetchone()

    pic_url = (
        user_res[2]
        if user_res[2]
        else fl.url_for("static", filename="img/undraw_profile.svg")
    )
    final_pic_url = f"{pic_url}?v={int(time.time())}"
    fl.session["profile_pic"] = final_pic_url

    user_data = {
        "username": user_res[0],
        "email": user_res[1],
        "profile_picture_url": final_pic_url,
    }

    sql_stapan = (
        "SELECT Nume, Prenume, Telefon, Adresa FROM STAPAN WHERE Id_user = :uid"
    )
    stapan_res = db.session.execute(text(sql_stapan), {"uid": user_id}).fetchone()
    stapan_data = {
        "nume": stapan_res[0] if stapan_res else "",
        "prenume": stapan_res[1] if stapan_res else "",
        "telefon": stapan_res[2] if stapan_res else "",
        "adresa": stapan_res[3] if stapan_res else "",
    }

    return fl.render_template("profile.html", user=user_data, stapan=stapan_data)


@app.route("/settings-page")
def show_settings_page():
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))
    user_data = {
        "username": fl.session.get("username", "User"),
        "profile_picture_url": fl.session.get("profile_pic", ""),
    }
    return fl.render_template("settings_page.html", user=user_data)


# =======================================================
# ZONA 3: ADMINISTRARE STĂPÂNI
# =======================================================


@app.route("/owner", methods=["GET", "POST"])
def show_owners_page():
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))

    user_id = fl.session["user_id"]

    if fl.request.method == "POST":
        try:
            nume = fl.request.form.get("nume")
            prenume = fl.request.form.get("prenume")
            telefon = fl.request.form.get("telefon")
            adresa = fl.request.form.get("adresa")

            check_sql = "SELECT Id_stapan FROM STAPAN WHERE Id_user = :uid"
            existing = db.session.execute(text(check_sql), {"uid": user_id}).fetchone()

            if existing:
                sql_upd = "UPDATE STAPAN SET Nume=:n, Prenume=:p, Telefon=:t, Adresa=:a WHERE Id_user=:uid"
                db.session.execute(
                    text(sql_upd),
                    {
                        "n": nume,
                        "p": prenume,
                        "t": telefon,
                        "a": adresa,
                        "uid": user_id,
                    },
                )
            else:
                sql_ins = "INSERT INTO STAPAN (Id_user, Nume, Prenume, Telefon, Adresa) VALUES (:uid, :n, :p, :t, :a)"
                db.session.execute(
                    text(sql_ins),
                    {
                        "uid": user_id,
                        "n": nume,
                        "p": prenume,
                        "t": telefon,
                        "a": adresa,
                    },
                )

            db.session.commit()
            return fl.redirect(fl.url_for("show_owners_page"))
        except Exception as e:
            db.session.rollback()
            fl.flash(f"Eroare: {e}", "danger")

    sql_stapan = "SELECT Id_stapan, Nume, Prenume, Telefon, Adresa FROM STAPAN WHERE Id_user = :uid"
    stapan_res = db.session.execute(text(sql_stapan), {"uid": user_id}).fetchone()

    user_data = {
        "username": fl.session.get("username", "User"),
        "profile_picture_url": fl.session.get(
            "profile_pic", fl.url_for("static", filename="img/undraw_profile.svg")
        ),
    }

    if stapan_res:
        stapan_id = stapan_res[0]
        sql_animale = "SELECT Id_animal, Nume, Specie, Rasa, Varsta, Sex FROM ANIMAL WHERE Id_stapan = :sid"
        animale_list = db.session.execute(
            text(sql_animale), {"sid": stapan_id}
        ).fetchall()
        stats = {"nr_animale": len(animale_list), "total_vizite": 0}

        return fl.render_template(
            "owner.html",
            user=user_data,
            setup_needed_owner=False,
            stapan={
                "nume": stapan_res[1],
                "prenume": stapan_res[2],
                "telefon": stapan_res[3],
                "adresa": stapan_res[4],
            },
            animale_list=animale_list,
            stats=stats,
        )
    else:
        return fl.render_template("owner.html", user=user_data, setup_needed_owner=True)


# =======================================================
# ZONA 4: ADMINISTRARE ANIMALE & ISTORIC MEDICAL
# =======================================================


@app.route("/animal", methods=["GET", "POST"])
def show_animal_page():
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))

    user_id = fl.session["user_id"]
    search_animal_id = fl.request.args.get("id", type=int)

    if fl.request.method == "POST":
        try:
            nume = fl.request.form.get("nume")
            specie = fl.request.form.get("specie")
            rasa = fl.request.form.get("rasa")
            varsta = fl.request.form.get("varsta")
            sex = fl.request.form.get("sex")

            sql_find_stapan = "SELECT Id_stapan FROM STAPAN WHERE Id_user = :uid"
            stapan_id = db.session.execute(
                text(sql_find_stapan), {"uid": user_id}
            ).scalar()

            if not stapan_id:
                fl.flash(
                    "Eroare: Trebuie să îți completezi profilul de stăpân mai întâi!",
                    "warning",
                )
                return fl.redirect(fl.url_for("show_owners_page"))

            sql_insert = """
                INSERT INTO ANIMAL (Nume, Specie, Rasa, Varsta, Sex, Id_stapan) 
                VALUES (:n, :s, :r, :v, :x, :sid)
            """
            db.session.execute(
                text(sql_insert),
                {
                    "n": nume,
                    "s": specie,
                    "r": rasa,
                    "v": varsta,
                    "x": sex,
                    "sid": stapan_id,
                },
            )
            db.session.commit()

            sql_get_new_id = "SELECT TOP 1 Id_animal FROM ANIMAL WHERE Id_stapan = :sid ORDER BY Id_animal DESC"
            new_animal_id = db.session.execute(
                text(sql_get_new_id), {"sid": stapan_id}
            ).scalar()

            fl.flash("Animal adăugat cu succes!", "success")
            return fl.redirect(fl.url_for("show_animal_page", id=new_animal_id))

        except Exception as e:
            db.session.rollback()
            fl.flash(f"Eroare la salvarea animalului: {e}", "danger")
            print(f"Eroare SQL: {e}")

    current_animal_id = None
    if search_animal_id:
        current_animal_id = search_animal_id
    else:
        sql_find = """
            SELECT TOP 1 A.Id_animal 
            FROM ANIMAL A 
            JOIN STAPAN S ON A.Id_stapan = S.Id_stapan 
            WHERE S.Id_user = :uid
        """
        current_animal_id = db.session.execute(
            text(sql_find), {"uid": user_id}
        ).scalar()

    user_data = {
        "username": fl.session.get("username", "User"),
        "profile_picture_url": fl.session.get(
            "profile_pic", fl.url_for("static", filename="img/undraw_profile.svg")
        ),
    }

    if current_animal_id:
        sql_animal = (
            "SELECT Nume, Specie, Rasa, Varsta, Sex FROM ANIMAL WHERE Id_animal = :aid"
        )
        animal_res = db.session.execute(
            text(sql_animal), {"aid": current_animal_id}
        ).fetchone()

        sql_istoric = """
            SELECT Id_fisa, Data_vizita, Motiv_vizita, Diagnostic, Greutate, Temperatura
            FROM FISA_MEDICALA
            WHERE Id_animal = :aid
            ORDER BY Data_vizita DESC
        """
        try:
            istoric_list = db.session.execute(
                text(sql_istoric), {"aid": current_animal_id}
            ).fetchall()
            print(f"DEBUG: Am gasit {len(istoric_list)} inregistrari.")
        except Exception as e:
            print(f"EROARE SQL: {e}")
            istoric_list = []

        vaccin_list = []
        try:
            sql_vaccin = "SELECT Id_vaccin, Data_vaccinare, Tip_vaccin, Data_rapel FROM VACCINARI WHERE Id_animal = :aid"
            vaccin_list = db.session.execute(
                text(sql_vaccin), {"aid": current_animal_id}
            ).fetchall()
        except:
            pass

        return fl.render_template(
            "animal.html",
            user=user_data,
            setup_needed_animal=False,
            animal=animal_res,
            istoric_list=istoric_list,
            vaccin_list=vaccin_list,
            current_animal_id=current_animal_id,
        )

    else:
        return fl.render_template(
            "animal.html", user=user_data, setup_needed_animal=True
        )


@app.route("/animal/new")
def add_new_animal():
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))

    user_data = {
        "username": fl.session.get("username", "User"),
        "profile_picture_url": fl.session.get(
            "profile_pic", fl.url_for("static", filename="img/undraw_profile.svg")
        ),
    }
    return fl.render_template("animal.html", user=user_data, setup_needed_animal=True)


@app.route("/animal/update/<int:animal_id>", methods=["POST"])
def update_animal_profile(animal_id):
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))

    try:
        nume = fl.request.form.get("nume")
        specie = fl.request.form.get("specie")
        rasa = fl.request.form.get("rasa")
        varsta = fl.request.form.get("varsta")
        sex = fl.request.form.get("sex")

        sql_update = """
            UPDATE ANIMAL 
            SET Nume = :n, Specie = :s, Rasa = :r, Varsta = :v, Sex = :x
            WHERE Id_animal = :aid
        """
        db.session.execute(
            text(sql_update),
            {
                "n": nume,
                "s": specie,
                "r": rasa,
                "v": varsta,
                "x": sex,
                "aid": animal_id,
            },
        )
        db.session.commit()
        fl.flash("Profilul animalului a fost actualizat!", "success")

    except Exception as e:
        db.session.rollback()
        fl.flash(f"Eroare la actualizare: {e}", "danger")

    return fl.redirect(fl.url_for("show_animal_page", id=animal_id))


@app.route("/animal/add-visit/<int:animal_id>", methods=["GET", "POST"])
def show_add_visit_form(animal_id):
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))

    if fl.request.method == "POST":
        try:
            data_vizita = fl.request.form.get("data_vizita")
            motiv = fl.request.form.get("motiv")
            diagnostic = fl.request.form.get("diagnostic")

            greutate = fl.request.form.get("greutate")
            greutate = float(greutate) if greutate and greutate.strip() else None

            temperatura = fl.request.form.get("temperatura")
            temperatura = (
                float(temperatura) if temperatura and temperatura.strip() else None
            )

            sql_fisa = """
                INSERT INTO FISA_MEDICALA (Id_animal, Data_vizita, Motiv_vizita, Diagnostic, Greutate, Temperatura)
                VALUES (:aid, :dv, :m, :d, :g, :t)
            """
            db.session.execute(
                text(sql_fisa),
                {
                    "aid": animal_id,
                    "dv": data_vizita,
                    "m": motiv,
                    "d": diagnostic,
                    "g": greutate,
                    "t": temperatura,
                },
            )

            tip_vaccin = fl.request.form.get("tip_vaccin")

            if tip_vaccin and tip_vaccin.strip():
                data_rapel = fl.request.form.get("data_rapel")

                if not data_rapel or not data_rapel.strip():
                    data_rapel = None

                sql_vaccin = """
                    INSERT INTO VACCINARI (Id_animal, Data_vaccinare, Tip_vaccin, Data_rapel)
                    VALUES (:aid, :dv, :tv, :dr)
                """
                db.session.execute(
                    text(sql_vaccin),
                    {
                        "aid": animal_id,
                        "dv": data_vizita,
                        "tv": tip_vaccin,
                        "dr": data_rapel,
                    },
                )

            db.session.commit()
            fl.flash("Vizită salvată cu succes!", "success")
            return fl.redirect(fl.url_for("show_animal_page", id=animal_id))

        except Exception as e:
            db.session.rollback()
            print(f"EROARE SQL ADD VISIT: {e}")
            fl.flash(f"Eroare la salvare: {e}", "danger")
            return fl.render_template(
                "Adding_new_interogation.html", animal_id=animal_id
            )

    return fl.render_template("Adding_new_interogation.html", animal_id=animal_id)


@app.route("/sterge_vizita/<int:id_fisa>", methods=["POST"])
def sterge_vizita(id_fisa):
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))

    sql_delete = "DELETE FROM FISA_MEDICALA WHERE Id_fisa = :fid"
    try:
        db.session.execute(text(sql_delete), {"fid": id_fisa})
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Eroare la ștergerea vizitei: {e}")

    return fl.redirect(fl.request.referrer)


@app.route("/sterge_vaccin/<int:id_vaccin>", methods=["POST"])
def sterge_vaccin(id_vaccin):
    sql_delete = "DELETE FROM VACCINARI WHERE Id_vaccin = :vid"
    try:
        db.session.execute(text(sql_delete), {"vid": id_vaccin})
        db.session.commit()
        fl.flash("Vaccin șters cu succes!", "success")
    except Exception as e:
        db.session.rollback()
        fl.flash(f"Eroare la ștergere: {e}", "danger")

    return fl.redirect(fl.request.referrer)


# =======================================================
# ZONA 5: PROGRAMĂRI
# =======================================================


@app.route("/appointments", methods=["GET", "POST"])
def show_appointments():
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))

    user_id = fl.session["user_id"]

    sql_stapan = "SELECT Id_stapan FROM STAPAN WHERE Id_user = :uid"
    stapan_id = db.session.execute(text(sql_stapan), {"uid": user_id}).scalar()

    if not stapan_id:
        fl.flash("Completează profilul de stăpân pentru a face programări.", "warning")
        return fl.redirect(fl.url_for("show_owners_page"))

    if fl.request.method == "POST":
        try:
            animal_id = fl.request.form.get("animal_select")
            data_ora_str = fl.request.form.get("data_ora")
            motiv = fl.request.form.get("motiv")

            data_ora = datetime.strptime(data_ora_str, "%Y-%m-%dT%H:%M")

            sql_insert = """
                INSERT INTO PROGRAMARI (Id_animal, Data_ora, Motiv, Status)
                VALUES (:aid, :do, :m, 'In Asteptare')
            """
            db.session.execute(
                text(sql_insert), {"aid": animal_id, "do": data_ora, "m": motiv}
            )
            db.session.commit()
            fl.flash("Programare trimisă cu succes!", "success")

        except Exception as e:
            db.session.rollback()
            fl.flash(f"Eroare programare: {e}", "danger")
            print(e)

        return fl.redirect(fl.url_for("show_appointments"))

    sql_animale = "SELECT Id_animal, Nume FROM ANIMAL WHERE Id_stapan = :sid"
    lista_animale = db.session.execute(text(sql_animale), {"sid": stapan_id}).fetchall()

    sql_programari = """
        SELECT 
            P.Id_programare,
            P.Data_ora,
            P.Motiv,
            P.Status,
            A.Nume as NumeAnimal,
            A.Specie
        FROM PROGRAMARI P
        JOIN ANIMAL A ON P.Id_animal = A.Id_animal
        WHERE A.Id_stapan = :sid
        ORDER BY P.Data_ora ASC
    """
    lista_programari = db.session.execute(
        text(sql_programari), {"sid": stapan_id}
    ).fetchall()

    nr_asteptare = sum(1 for p in lista_programari if p.Status == "In Asteptare")
    nr_confirmet = sum(1 for p in lista_programari if p.Status == "Confirmat")

    user_data = {
        "username": fl.session.get("username", "User"),
        "profile_picture_url": fl.session.get(
            "profile_pic", fl.url_for("static", filename="img/undraw_profile.svg")
        ),
    }

    return fl.render_template(
        "appointments.html",
        user=user_data,
        lista_animale=lista_animale,
        lista_programari=lista_programari,
        stats={"asteptare": nr_asteptare, "confirmat": nr_confirmet},
    )


@app.route(
    "/update_programare/<int:id_programare>/<string:actiune>", methods=["GET", "POST"]
)
def update_programare(id_programare, actiune):
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))

    status_nou = ""
    if actiune == "confirma":
        status_nou = "Confirmat"
    elif actiune == "anuleaza":
        status_nou = "Anulat"

    sql_update = "UPDATE PROGRAMARI SET Status = :st WHERE Id_programare = :idp"

    try:
        db.session.execute(text(sql_update), {"st": status_nou, "idp": id_programare})
        db.session.commit()
        fl.flash(f"Programarea a fost actualizată: {status_nou}", "success")
    except Exception as e:
        db.session.rollback()
        fl.flash(f"Eroare: {e}", "danger")

    return fl.redirect(fl.request.referrer)


# =======================================================
# ZONA 6: FINANCIAR (PLĂȚI & FACTURI)
# =======================================================


@app.route("/plati")
def show_payments_page():
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))

    user_id = fl.session["user_id"]

    sql_stapan = "SELECT Id_stapan FROM STAPAN WHERE Id_user = :uid"
    stapan_id = db.session.execute(text(sql_stapan), {"uid": user_id}).scalar()

    if not stapan_id:
        fl.flash("Nu ai un profil de stăpân asociat.", "warning")
        return fl.redirect(fl.url_for("index"))

    sql_plati = """
        SELECT Id_plata, Data_plata, Descriere, Suma, Status 
        FROM PLATI 
        WHERE Id_stapan = :sid 
        ORDER BY Data_plata DESC
    """
    plati_list = db.session.execute(text(sql_plati), {"sid": stapan_id}).fetchall()

    total_cheltuit = sum(p.Suma for p in plati_list if p.Status == "Achitat")

    user_data = {
        "username": fl.session.get("username", "User"),
        "profile_picture_url": fl.session.get(
            "profile_pic", fl.url_for("static", filename="img/undraw_profile.svg")
        ),
    }

    return fl.render_template(
        "payments.html", user=user_data, plati=plati_list, total=total_cheltuit
    )


@app.route("/factura/<int:id_plata>")
def generate_invoice(id_plata):
    if "user_id" not in fl.session:
        return fl.redirect(fl.url_for("show_login_page"))

    sql = """
        SELECT P.Descriere, P.Suma, P.Data_plata, P.Status, S.Nume, S.Prenume, S.Adresa
        FROM PLATI P
        JOIN STAPAN S ON P.Id_stapan = S.Id_stapan
        WHERE P.Id_plata = :pid
    """
    plata = db.session.execute(text(sql), {"pid": id_plata}).fetchone()

    if not plata:
        return "Plata nu a fost găsită.", 404

    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Arial", "B", 20)
    pdf.cell(0, 10, "FACTURA SERVICII VETERINARE", ln=True, align="C")
    pdf.ln(10)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Furnizor: Puppy Vet Clinic", ln=True)
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, "Str. Exemplului nr. 10, Bucuresti", ln=True)
    pdf.cell(0, 10, "CIF: RO12345678", ln=True)
    pdf.ln(10)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, f"Client: {plata.Nume} {plata.Prenume}", ln=True)
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Adresa: {plata.Adresa}", ln=True)
    pdf.ln(20)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(130, 10, "Descriere Serviciu", border=1)
    pdf.cell(60, 10, "Pret (RON)", border=1, ln=True, align="C")

    pdf.set_font("Arial", "", 12)
    pdf.cell(130, 10, f"{plata.Descriere}", border=1)
    pdf.cell(60, 10, f"{plata.Suma:.2f}", border=1, ln=True, align="C")

    pdf.ln(5)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(130, 10, "TOTAL DE PLATA:", align="R")
    pdf.cell(60, 10, f"{plata.Suma:.2f} RON", border=1, align="C", ln=True)

    pdf.ln(30)
    pdf.set_font("Arial", "I", 10)
    pdf.cell(
        0, 10, f"Data emiterii: {plata.Data_plata.strftime('%d-%m-%Y')}", align="L"
    )
    pdf.cell(0, 10, "Multumim ca ati ales Puppy Vet!", align="R")

    buffer = io.BytesIO()
    pdf_content = pdf.output(dest="S").encode("latin-1")
    buffer.write(pdf_content)
    buffer.seek(0)

    return fl.send_file(
        buffer,
        as_attachment=True,
        download_name=f"Factura_{id_plata}.pdf",
        mimetype="application/pdf",
    )


# =======================================================
# ZONA 7: UTILITARE & RULARE
# =======================================================


@app.context_processor
def inject_notifications():
    if "user_id" not in fl.session:
        return dict(notificari=[], nr_notificari=0)

    notificari = []

    try:
        sql_pending = """
            SELECT p.Id_programare, p.Data_ora, a.Nume as NumeAnimal 
            FROM PROGRAMARI p
            JOIN ANIMALE a ON p.Id_animal = a.Id_animal
            WHERE p.Status = 'In Asteptare'
            ORDER BY p.Data_ora ASC
        """
        pending = db.session.execute(text(sql_pending)).fetchall()

        for p in pending:
            notificari.append(
                {
                    "tip": "warning",
                    "icon": "fa-exclamation-triangle",
                    "titlu": f"Cerere: {p.NumeAnimal}",
                    "timp": p.Data_ora.strftime("%d %b %H:%M"),
                    "link": fl.url_for("show_appointments"),
                }
            )

        sql_today = """
            SELECT p.Id_programare, p.Data_ora, a.Nume as NumeAnimal, p.Motiv
            FROM PROGRAMARI p
            JOIN ANIMALE a ON p.Id_animal = a.Id_animal
            WHERE p.Status = 'Confirmat'
        """
        all_confirmed = db.session.execute(text(sql_today)).fetchall()

        today_date = date.today()
        for p in all_confirmed:
            if p.Data_ora.date() == today_date:
                notificari.append(
                    {
                        "tip": "info",
                        "icon": "fa-calendar-check",
                        "titlu": f"Azi: {p.NumeAnimal}",
                        "timp": p.Data_ora.strftime("%H:%M") + f" ({p.Motiv})",
                        "link": fl.url_for("show_appointments"),
                    }
                )

    except Exception as e:
        print(f"Eroare notificari: {e}")

    return dict(notificari=notificari, nr_notificari=len(notificari))


if __name__ == "__main__":
    app.run(debug=True)
