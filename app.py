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
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from functools import wraps
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
    name="facebook",
    client_id=os.getenv("FACEBOOK_CLIENT_ID"),
    client_secret=os.getenv("FACEBOOK_CLIENT_SECRET"),
    access_token_url="https://graph.facebook.com/oauth/access_token",
    access_token_params=None,
    authorize_url="https://www.facebook.com/dialog/oauth",
    authorize_params=None,
    api_base_url="https://graph.facebook.com/",
    client_kwargs={"scope": "email public_profile"},
)

app.config["SECRET_KEY"] = "o_cheie_secreta_foarte_complicata"
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False

Session(app)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "mssql+pyodbc:///?odbc_connect=DRIVER={ODBC+Driver+17+for+SQL+Server};SERVER=VASIVBM\\SQLEXPRESS;DATABASE=CabinetVeterinar;Trusted_Connection=yes;"
)

db = SQLAlchemy(app)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in fl.session:
            return fl.redirect(fl.url_for("show_login_page"))
        return f(*args, **kwargs)

    return decorated_function


def get_current_stapan_id(user_id):
    sql = "SELECT Id_stapan FROM STAPAN WHERE Id_user = :uid"
    return db.session.execute(text(sql), {"uid": user_id}).scalar()


def _set_user_session(user_id, username, email, picture=None):
    fl.session["logged_in"] = True
    fl.session["user_id"] = user_id
    fl.session["username"] = username
    fl.session["email"] = email
    # Dacă nu are poză, punem una default
    if not picture:
        picture = fl.url_for("static", filename="img/default_avatar.jpg")
    fl.session["profile_pic"] = picture


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
            return fl.redirect(fl.url_for("show_login_page"))

        try:
            # Selectăm și Poza (Profile_Pic) direct, ca să o avem în sesiune
            sql_select = "SELECT Parola, Username, Id_user, Profile_Pic FROM USER_ACCOUNT WHERE Email = :email"
            user_record = db.session.execute(
                text(sql_select), {"email": email}
            ).fetchone()

            if not user_record:
                fl.flash("Email sau parolă incorectă.", "danger")
                return fl.redirect(fl.url_for("show_login_page"))

            # Verificare Parolă
            stored_parola = user_record[0]
            if not bcrypt.checkpw(
                password.encode("utf-8"), stored_parola.encode("utf-8")
            ):
                fl.flash("Email sau parolă incorectă.", "danger")
                return fl.redirect(fl.url_for("show_login_page"))

            # LOGIN REUȘIT -> Folosim Helper-ul
            _set_user_session(user_record[2], user_record[1], email, user_record[3])

            response = fl.make_response(fl.redirect(fl.url_for("index")))

            # Logică Remember Me
            if remember_me:
                expires = datetime.now() + timedelta(days=30)
                response.set_cookie(
                    "remember_email", email, expires=expires, httponly=True
                )
            else:
                response.delete_cookie("remember_email")

            return response

        except Exception as e:
            print(f"Eroare Login: {e}")
            fl.flash("Eroare server.", "danger")
            return fl.redirect(fl.url_for("show_login_page"))

    # GET Request
    return fl.render_template(
        "login.html", remembered_email=fl.request.cookies.get("remember_email")
    )


@app.route("/register", methods=["GET", "POST"])
def show_register_page():
    if fl.request.method == "POST":
        username = fl.request.form.get("username")
        email = fl.request.form.get("email")
        password = fl.request.form.get("password")
        retype = fl.request.form.get("retype_password")

        if not all([username, email, password, retype]) or password != retype:
            return "ERROR: Date invalide sau parolele nu coincid.", 400

        if len(password) < 8:
            return "ERROR: Parola minim 8 caractere.", 400

        try:
            # Verificăm dacă există deja
            sql_check = "SELECT 1 FROM USER_ACCOUNT WHERE Username = :u OR Email = :e"
            if db.session.execute(
                text(sql_check), {"u": username, "e": email}
            ).fetchone():
                return "ERROR: User/Email există deja.", 409

            # Hash și Insert
            hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(
                "utf-8"
            )

            sql_insert = (
                "INSERT INTO USER_ACCOUNT (Username, Email, Parola) VALUES (:u, :e, :p)"
            )
            db.session.execute(
                text(sql_insert), {"u": username, "e": email, "p": hashed}
            )
            db.session.commit()

            return fl.redirect(fl.url_for("show_login_page"))

        except Exception as ex:
            db.session.rollback()
            print(f"Eroare Register: {ex}")
            return "Eroare server.", 500

    return fl.render_template("register.html")


# --- FUNCȚIA CENTRALIZATĂ PENTRU OAUTH (Google & Facebook) ---
def handle_oauth_login(email, name, picture):
    """
    Gestionează automat logica de verificare/creare user
    și setare sesiune pentru orice provider OAuth.
    """
    try:
        sql_find = (
            "SELECT Id_user, Username, Profile_Pic FROM USER_ACCOUNT WHERE Email = :e"
        )
        existing = db.session.execute(text(sql_find), {"e": email}).fetchone()

        user_id = None
        current_name = None

        if existing:
            # --- UPDATE USER EXISTENT ---
            user_id = existing[0]
            current_name = existing[1]

            # Actualizăm numele doar dacă e diferit și valid
            final_name = name if (name and name != current_name) else current_name

            sql_update = "UPDATE USER_ACCOUNT SET Profile_Pic = :pic, Username = :name WHERE Id_user = :uid"
            db.session.execute(
                text(sql_update), {"pic": picture, "name": final_name, "uid": user_id}
            )

            # Actualizăm variabilele locale pentru sesiune
            current_name = final_name

        else:
            # --- INSERT USER NOU ---
            import uuid

            # Generăm parolă random pentru consistență (nu va fi folosită la login)
            rand_pass = bcrypt.hashpw(
                str(uuid.uuid4()).encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")

            sql_ins = "INSERT INTO USER_ACCOUNT (Email, Username, Parola, Profile_Pic) VALUES (:e, :u, :p, :pic)"
            db.session.execute(
                text(sql_ins), {"e": email, "u": name, "p": rand_pass, "pic": picture}
            )

            # Luăm ID-ul nou generat
            new_user = db.session.execute(text(sql_find), {"e": email}).fetchone()
            user_id = new_user[0]
            current_name = name

        db.session.commit()

        # Setăm sesiunea folosind helper-ul nostru
        _set_user_session(user_id, current_name, email, picture)
        return True

    except Exception as e:
        db.session.rollback()
        print(f"OAuth Error: {e}")
        return False


# --- CALLBACK-URI OAUTH (Folosesc funcția centralizată handle_oauth_login) ---
@app.route("/login/google")
def google_login():
    # Trimitem userul către Google
    redirect_uri = fl.url_for("google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/login/facebook")
def facebook_login():
    # Trimitem userul către Facebook (Hardcodat localhost pentru siguranță)
    redirect_uri = "http://localhost:5000/login/facebook/callback"
    return facebook.authorize_redirect(redirect_uri)


@app.route("/login/google/callback")
def google_callback():
    try:
        token = google.authorize_access_token()
        user_info = token.get("userinfo")

        # Apelăm funcția noastră universală
        if handle_oauth_login(
            user_info.get("email"), user_info.get("name"), user_info.get("picture")
        ):
            return fl.redirect(fl.url_for("index"))

        fl.flash("Eroare la procesarea datelor Google.", "danger")
    except Exception as e:
        print(f"Eroare Google Callback: {e}")
        fl.flash("Nu s-a putut finaliza autentificarea cu Google.", "danger")

    return fl.redirect(fl.url_for("show_login_page"))


@app.route("/login/facebook/callback")
def facebook_callback():
    try:
        token = facebook.authorize_access_token()
        resp = facebook.get("me?fields=id,name,email,picture.type(large)")
        profile = resp.json()

        # Logică extragere poză FB
        picture_url = (
            profile.get("picture", {})
            .get("data", {})
            .get("url", fl.url_for("static", filename="img/default_avatar.jpg"))
        )
        # Fallback email
        email = profile.get("email") or f"{profile.get('id')}@facebook.com"

        # Apelăm funcția noastră universală
        if handle_oauth_login(email, profile.get("name"), picture_url):
            return fl.redirect(fl.url_for("index"))

        fl.flash("Eroare la procesarea datelor Facebook.", "danger")
    except Exception as e:
        print(f"Eroare Facebook Callback: {e}")
        fl.flash("Nu s-a putut finaliza autentificarea cu Facebook.", "danger")

    return fl.redirect(fl.url_for("show_login_page"))


# --- RESETARE PAROLĂ (Flux Simplificat și Comasat) ---


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password_page():
    if fl.request.method == "POST":
        email = fl.request.form.get("email")

        if not email:
            fl.flash("Te rog completează adresa de email.", "warning")
        else:
            try:
                # Verificăm rapid dacă există emailul
                if db.session.execute(
                    text("SELECT 1 FROM USER_ACCOUNT WHERE Email = :e"), {"e": email}
                ).fetchone():
                    fl.session["reset_email"] = email
                    fl.flash("Adresa confirmată. Introdu noua parolă.", "success")
                    return fl.redirect(fl.url_for("retype_password_page"))
                else:
                    fl.flash("Email-ul nu a fost găsit în baza de date.", "danger")
            except Exception as ex:
                print(f"Eroare Forgot Password: {ex}")
                fl.flash("Eroare server.", "danger")

    return fl.render_template("forgot-password.html")


@app.route("/retype-password", methods=["GET", "POST"])
def retype_password_page():
    # Securitate: Nu lăsăm pe nimeni aici fără email confirmat
    if "reset_email" not in fl.session:
        fl.flash("Sesiunea a expirat. Reia procesul.", "warning")
        return fl.redirect(fl.url_for("forgot_password_page"))

    if fl.request.method == "POST":
        password = fl.request.form.get("password")
        retype = fl.request.form.get("retype_password")

        if not password or password != retype:
            fl.flash("Parolele nu se potrivesc sau sunt goale.", "danger")
        else:
            try:
                email = fl.session["reset_email"]
                hashed = bcrypt.hashpw(
                    password.encode("utf-8"), bcrypt.gensalt()
                ).decode("utf-8")

                db.session.execute(
                    text("UPDATE USER_ACCOUNT SET Parola = :p WHERE Email = :e"),
                    {"p": hashed, "e": email},
                )
                db.session.commit()

                # Curățăm sesiunea și trimitem la login
                fl.session.pop("reset_email", None)
                fl.flash("Parola a fost schimbată cu succes! Te poți loga.", "success")
                return fl.redirect(fl.url_for("show_login_page"))

            except Exception as ex:
                db.session.rollback()
                print(f"Eroare Reset Password: {ex}")
                fl.flash("Eroare la actualizarea parolei.", "danger")

    return fl.render_template("retype_password.html")


@app.route("/logout")
def logout():
    fl.session.clear()
    fl.flash("Te-ai delogat cu succes.", "info")
    return fl.redirect(fl.url_for("show_login_page"))


# =======================================================
# ZONA 2: DASHBOARD & NAVIGARE PRINCIPALĂ
# =======================================================


# =======================================================
# ZONA 2: DASHBOARD & NAVIGARE PRINCIPALĂ
# =======================================================


@app.route("/")
@login_required
def index():
    # Statistici simple
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

    # Activitate lunară
    sql_luna = """
        SELECT COUNT(Id_fisa) FROM FISA_MEDICALA
        WHERE MONTH(Data_vizita) = MONTH(GETDATE()) AND YEAR(Data_vizita) = YEAR(GETDATE())
    """
    card_activitate_luna = db.session.execute(text(sql_luna)).scalar() or 0

    # Date Grafic Pie (Optimizat cu List Comprehension)
    rezultat_pie = db.session.execute(
        text("SELECT Specie, COUNT(Id_animal) FROM ANIMAL GROUP BY Specie")
    ).fetchall()

    pie_labels_json = json.dumps([row[0] for row in rezultat_pie])
    pie_values_json = json.dumps([row[1] for row in rezultat_pie])

    # NOTĂ: Nu mai trimitem 'user=user_data', se ocupă context_processor-ul global
    return fl.render_template(
        "dashboard.html",
        nr_animale=card_animale,
        nr_stapani=card_stapani,
        nr_consultatii=card_consultatii,
        nr_activitate_luna=card_activitate_luna,
        pie_labels_json=pie_labels_json,
        pie_values_json=pie_values_json,
    )


@app.route("/search")
@login_required
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
    results = db.session.execute(text(sql_search), {"q": f"%{query}%"}).fetchall()

    if len(results) == 1:
        return fl.redirect(fl.url_for("show_animal_page", id=results[0].Id_animal))
    elif len(results) > 1:
        fl.flash(f"Găsite {len(results)} rezultate. Afișăm primul.", "info")
        return fl.redirect(fl.url_for("show_animal_page", id=results[0].Id_animal))
    else:
        fl.flash("Niciun rezultat găsit.", "danger")
        return fl.redirect(fl.url_for("show_animal_page"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def show_profile_page():
    user_id = fl.session["user_id"]

    if fl.request.method == "POST":
        try:
            # Colectăm datele
            data = {
                "n": fl.request.form.get("nume"),
                "p": fl.request.form.get("prenume"),
                "t": fl.request.form.get("telefon"),
                "a": fl.request.form.get("adresa"),
                "uid": user_id,
            }

            # Verificăm dacă există profilul de stăpân (pentru a decide UPDATE sau INSERT)
            # Folosim SELECT 1 pentru eficiență maximă
            exists = db.session.execute(
                text("SELECT 1 FROM STAPAN WHERE Id_user = :uid"), {"uid": user_id}
            ).fetchone()

            if exists:
                sql_cmd = "UPDATE STAPAN SET Nume=:n, Prenume=:p, Telefon=:t, Adresa=:a WHERE Id_user=:uid"
            else:
                sql_cmd = "INSERT INTO STAPAN (Id_user, Nume, Prenume, Telefon, Adresa) VALUES (:uid, :n, :p, :t, :a)"

            db.session.execute(text(sql_cmd), data)

            # Gestionare Poză Profil
            file = fl.request.files.get("file_poza")
            if file and file.filename:
                filename = secure_filename(file.filename)
                save_path = os.path.join(app.root_path, "static/img", filename)
                file.save(save_path)

                # Actualizăm URL-ul pozei în DB și Sesiune
                new_pic_url = fl.url_for("static", filename=f"img/{filename}")
                db.session.execute(
                    text(
                        "UPDATE USER_ACCOUNT SET Profile_Pic = :pic WHERE Id_user = :uid"
                    ),
                    {"pic": new_pic_url, "uid": user_id},
                )
                fl.session["profile_pic"] = new_pic_url

            db.session.commit()
            fl.flash("Profil actualizat cu succes!", "success")

        except Exception as e:
            db.session.rollback()
            fl.flash(f"Eroare la salvare: {e}", "danger")

    # Date Stăpân pentru formular
    sql_stapan = (
        "SELECT Nume, Prenume, Telefon, Adresa FROM STAPAN WHERE Id_user = :uid"
    )
    res = db.session.execute(text(sql_stapan), {"uid": user_id}).fetchone()

    stapan_data = {
        "nume": res[0] if res else "",
        "prenume": res[1] if res else "",
        "telefon": res[2] if res else "",
        "adresa": res[3] if res else "",
    }

    return fl.render_template("profile.html", stapan=stapan_data)


@app.route("/settings-page")
@login_required
def show_settings_page():
    # Simplificat la maxim - user data vine automat
    return fl.render_template("settings_page.html")


# =======================================================
# ZONA 3: ADMINISTRARE STĂPÂNI
# =======================================================


@app.route("/owner", methods=["GET", "POST"])
@login_required
def show_owners_page():
    user_id = fl.session["user_id"]

    if fl.request.method == "POST":
        try:
            # Colectăm datele din formular
            data = {
                "n": fl.request.form.get("nume"),
                "p": fl.request.form.get("prenume"),
                "t": fl.request.form.get("telefon"),
                "a": fl.request.form.get("adresa"),
                "uid": user_id,
            }

            # Verificăm dacă există deja (Folosim helper-ul creat anterior sau query direct)
            # Aici e mai rapid un query simplu de check
            exists = db.session.execute(
                text("SELECT 1 FROM STAPAN WHERE Id_user = :uid"), {"uid": user_id}
            ).fetchone()

            if exists:
                sql_cmd = "UPDATE STAPAN SET Nume=:n, Prenume=:p, Telefon=:t, Adresa=:a WHERE Id_user=:uid"
            else:
                sql_cmd = "INSERT INTO STAPAN (Id_user, Nume, Prenume, Telefon, Adresa) VALUES (:uid, :n, :p, :t, :a)"

            db.session.execute(text(sql_cmd), data)
            db.session.commit()
            return fl.redirect(fl.url_for("show_owners_page"))

        except Exception as e:
            db.session.rollback()
            fl.flash(f"Eroare: {e}", "danger")

    # GET Request - Afișare date
    sql_stapan = "SELECT Id_stapan, Nume, Prenume, Telefon, Adresa FROM STAPAN WHERE Id_user = :uid"
    stapan_res = db.session.execute(text(sql_stapan), {"uid": user_id}).fetchone()

    if stapan_res:
        stapan_id = stapan_res[0]
        # Luăm animalele pentru lista din dreapta
        sql_animale = "SELECT Id_animal, Nume, Specie, Rasa, Varsta, Sex FROM ANIMAL WHERE Id_stapan = :sid"
        animale_list = db.session.execute(
            text(sql_animale), {"sid": stapan_id}
        ).fetchall()

        return fl.render_template(
            "owner.html",
            setup_needed_owner=False,
            stapan={
                "nume": stapan_res[1],
                "prenume": stapan_res[2],
                "telefon": stapan_res[3],
                "adresa": stapan_res[4],
            },
            animale_list=animale_list,
            stats={"nr_animale": len(animale_list), "total_vizite": 0},
        )
    else:
        return fl.render_template("owner.html", setup_needed_owner=True)


# =======================================================
# ZONA 4: ADMINISTRARE ANIMALE & ISTORIC MEDICAL
# =======================================================


@app.route("/animal", methods=["GET", "POST"])
@login_required
def show_animal_page():
    user_id = fl.session["user_id"]
    search_animal_id = fl.request.args.get("id", type=int)

    # --- LOGICA POST (Adăugare Animal) ---
    if fl.request.method == "POST":
        try:
            # Folosim helper-ul pentru a lua ID-ul stăpânului
            stapan_id = get_current_stapan_id(user_id)

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
            # Executăm insert-ul
            db.session.execute(
                text(sql_insert),
                {
                    "n": fl.request.form.get("nume"),
                    "s": fl.request.form.get("specie"),
                    "r": fl.request.form.get("rasa"),
                    "v": fl.request.form.get("varsta"),
                    "x": fl.request.form.get("sex"),
                    "sid": stapan_id,
                },
            )
            db.session.commit()

            # Luăm ID-ul noului animal pentru redirect
            new_id = db.session.execute(
                text(
                    "SELECT TOP 1 Id_animal FROM ANIMAL WHERE Id_stapan = :sid ORDER BY Id_animal DESC"
                ),
                {"sid": stapan_id},
            ).scalar()

            fl.flash("Animal adăugat cu succes!", "success")
            return fl.redirect(fl.url_for("show_animal_page", id=new_id))

        except Exception as e:
            db.session.rollback()
            fl.flash(f"Eroare la salvare: {e}", "danger")
            print(f"Eroare SQL: {e}")

    # --- LOGICA GET (Afișare Animal) ---
    current_animal_id = search_animal_id

    # Dacă nu s-a cerut un ID specific, îl căutăm pe primul al utilizatorului
    if not current_animal_id:
        sql_find = """
            SELECT TOP 1 A.Id_animal FROM ANIMAL A 
            JOIN STAPAN S ON A.Id_stapan = S.Id_stapan 
            WHERE S.Id_user = :uid
        """
        current_animal_id = db.session.execute(
            text(sql_find), {"uid": user_id}
        ).scalar()

    if current_animal_id:
        # 1. Date Animal
        animal_res = db.session.execute(
            text(
                "SELECT Nume, Specie, Rasa, Varsta, Sex FROM ANIMAL WHERE Id_animal = :aid"
            ),
            {"aid": current_animal_id},
        ).fetchone()

        # 2. Istoric Medical
        sql_istoric = """
            SELECT Id_fisa, Data_vizita, Motiv_vizita, Diagnostic, Greutate, Temperatura
            FROM FISA_MEDICALA WHERE Id_animal = :aid ORDER BY Data_vizita DESC
        """
        istoric_list = (
            db.session.execute(text(sql_istoric), {"aid": current_animal_id}).fetchall()
            or []
        )

        # 3. Vaccinuri (Gestionăm eroarea tabel lipsă elegant)
        vaccin_list = []
        try:
            vaccin_list = db.session.execute(
                text(
                    "SELECT Id_vaccin, Data_vaccinare, Tip_vaccin, Data_rapel FROM VACCINARI WHERE Id_animal = :aid"
                ),
                {"aid": current_animal_id},
            ).fetchall()
        except:
            pass  # Tabelul poate nu există încă

        return fl.render_template(
            "animal.html",
            setup_needed_animal=False,
            animal=animal_res,
            istoric_list=istoric_list,
            vaccin_list=vaccin_list,
            current_animal_id=current_animal_id,
        )

    else:
        # CAZUL FĂRĂ ANIMALE (Fix pentru erorile Undefined)
        return fl.render_template(
            "animal.html",
            setup_needed_animal=True,
            animal=None,
            current_animal_id=0,  # Critic pentru a preveni erorile de url_for
            istoric_list=[],
            vaccin_list=[],
        )


@app.route("/animal/new")
@login_required
def add_new_animal():
    # Adăugăm parametrii de siguranță pentru a preveni erori în template
    return fl.render_template(
        "animal.html",
        setup_needed_animal=True,
        animal=None,
        current_animal_id=0,
        istoric_list=[],
        vaccin_list=[],
    )


@app.route("/animal/update/<int:animal_id>", methods=["POST"])
@login_required
def update_animal_profile(animal_id):
    try:
        # Colectăm datele într-un dicționar curat
        data = {
            "n": fl.request.form.get("nume"),
            "s": fl.request.form.get("specie"),
            "r": fl.request.form.get("rasa"),
            "v": fl.request.form.get("varsta"),
            "x": fl.request.form.get("sex"),
            "aid": animal_id,
        }

        sql_update = """
            UPDATE ANIMAL 
            SET Nume = :n, Specie = :s, Rasa = :r, Varsta = :v, Sex = :x
            WHERE Id_animal = :aid
        """
        db.session.execute(text(sql_update), data)
        db.session.commit()
        fl.flash("Profilul animalului a fost actualizat!", "success")

    except Exception as e:
        db.session.rollback()
        fl.flash(f"Eroare la actualizare: {e}", "danger")

    return fl.redirect(fl.url_for("show_animal_page", id=animal_id))


@app.route("/animal/add-visit/<int:animal_id>", methods=["GET", "POST"])
@login_required
def show_add_visit_form(animal_id):
    if fl.request.method == "POST":
        try:
            # Procesare date numerice (float) cu verificare
            greutate = fl.request.form.get("greutate", "").strip()
            temperatura = fl.request.form.get("temperatura", "").strip()

            # Structurăm datele vizitei
            fisa_data = {
                "aid": animal_id,
                "dv": fl.request.form.get("data_vizita"),
                "m": fl.request.form.get("motiv"),
                "d": fl.request.form.get("diagnostic"),
                "g": float(greutate) if greutate else None,
                "t": float(temperatura) if temperatura else None,
            }

            sql_fisa = """
                INSERT INTO FISA_MEDICALA (Id_animal, Data_vizita, Motiv_vizita, Diagnostic, Greutate, Temperatura)
                VALUES (:aid, :dv, :m, :d, :g, :t)
            """
            db.session.execute(text(sql_fisa), fisa_data)

            # --- Logica pentru Vaccin (Opțional) ---
            tip_vaccin = fl.request.form.get("tip_vaccin", "").strip()
            if tip_vaccin:
                rapel = fl.request.form.get("data_rapel", "").strip()

                sql_vaccin = """
                    INSERT INTO VACCINARI (Id_animal, Data_vaccinare, Tip_vaccin, Data_rapel)
                    VALUES (:aid, :dv, :tv, :dr)
                """
                db.session.execute(
                    text(sql_vaccin),
                    {
                        "aid": animal_id,
                        "dv": fisa_data["dv"],  # Folosim aceeași dată ca la vizită
                        "tv": tip_vaccin,
                        "dr": rapel if rapel else None,
                    },
                )

            db.session.commit()
            fl.flash("Vizită salvată cu succes!", "success")
            return fl.redirect(fl.url_for("show_animal_page", id=animal_id))

        except Exception as e:
            db.session.rollback()
            print(f"EROARE SQL ADD VISIT: {e}")
            fl.flash(f"Eroare la salvare: {e}", "danger")
            # În caz de eroare rămânem pe pagină
            return fl.render_template(
                "Adding_new_interogation.html", animal_id=animal_id
            )

    return fl.render_template("Adding_new_interogation.html", animal_id=animal_id)


@app.route("/sterge_vizita/<int:id_fisa>", methods=["POST"])
@login_required
def sterge_vizita(id_fisa):
    try:
        db.session.execute(
            text("DELETE FROM FISA_MEDICALA WHERE Id_fisa = :fid"), {"fid": id_fisa}
        )
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Eroare la ștergerea vizitei: {e}")
    return fl.redirect(fl.request.referrer)


@app.route("/sterge_vaccin/<int:id_vaccin>", methods=["POST"])
@login_required
def sterge_vaccin(id_vaccin):
    try:
        db.session.execute(
            text("DELETE FROM VACCINARI WHERE Id_vaccin = :vid"), {"vid": id_vaccin}
        )
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
@login_required
def show_appointments():
    user_id = fl.session["user_id"]

    # Folosim helper-ul nostru pentru a evita cod duplicat
    stapan_id = get_current_stapan_id(user_id)

    if not stapan_id:
        fl.flash("Completează profilul de stăpân pentru a face programări.", "warning")
        return fl.redirect(fl.url_for("show_owners_page"))

    if fl.request.method == "POST":
        try:
            # Parsăm data
            data_ora = datetime.strptime(
                fl.request.form.get("data_ora"), "%Y-%m-%dT%H:%M"
            )

            sql_insert = "INSERT INTO PROGRAMARI (Id_animal, Data_ora, Motiv, Status) VALUES (:aid, :do, :m, 'In Asteptare')"
            db.session.execute(
                text(sql_insert),
                {
                    "aid": fl.request.form.get("animal_select"),
                    "do": data_ora,
                    "m": fl.request.form.get("motiv"),
                },
            )
            db.session.commit()
            fl.flash("Programare trimisă cu succes!", "success")

        except Exception as e:
            db.session.rollback()
            fl.flash(f"Eroare programare: {e}", "danger")
            print(e)

        return fl.redirect(fl.url_for("show_appointments"))

    # Preluare date pentru afișare
    sql_animale = "SELECT Id_animal, Nume FROM ANIMAL WHERE Id_stapan = :sid"
    lista_animale = db.session.execute(text(sql_animale), {"sid": stapan_id}).fetchall()

    sql_programari = """
        SELECT P.Id_programare, P.Data_ora, P.Motiv, P.Status, A.Nume as NumeAnimal, A.Specie
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

    return fl.render_template(
        "appointments.html",
        lista_animale=lista_animale,
        lista_programari=lista_programari,
        stats={"asteptare": nr_asteptare, "confirmat": nr_confirmet},
    )


@app.route(
    "/update_programare/<int:id_programare>/<string:actiune>", methods=["GET", "POST"]
)
@login_required
def update_programare(id_programare, actiune):
    status_nou = ""
    if actiune == "confirma":
        status_nou = "Confirmat"
    elif actiune == "anuleaza":
        status_nou = "Anulat"

    try:
        sql_update = "UPDATE PROGRAMARI SET Status = :st WHERE Id_programare = :idp"
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
@login_required
def show_payments_page():
    user_id = fl.session["user_id"]
    stapan_id = get_current_stapan_id(user_id)

    if not stapan_id:
        fl.flash("Nu ai un profil de stăpân asociat.", "warning")
        return fl.redirect(fl.url_for("index"))

    sql_plati = """
        SELECT Id_plata, Data_plata, Descriere, Suma, Status 
        FROM PLATI WHERE Id_stapan = :sid ORDER BY Data_plata DESC
    """
    plati_list = db.session.execute(text(sql_plati), {"sid": stapan_id}).fetchall()

    total_cheltuit = sum(p.Suma for p in plati_list if p.Status == "Achitat")

    return fl.render_template("payments.html", plati=plati_list, total=total_cheltuit)


@app.route("/factura/<int:id_plata>")
@login_required
def generate_invoice(id_plata):
    sql = """
        SELECT P.Descriere, P.Suma, P.Data_plata, P.Status, S.Nume, S.Prenume, S.Adresa
        FROM PLATI P
        JOIN STAPAN S ON P.Id_stapan = S.Id_stapan
        WHERE P.Id_plata = :pid
    """
    plata = db.session.execute(text(sql), {"pid": id_plata}).fetchone()

    if not plata:
        return "Plata nu a fost găsită.", 404

    # Generare PDF
    pdf = FPDF()
    pdf.add_page()

    # Header Factura
    pdf.set_font("Arial", "B", 20)
    pdf.cell(0, 10, "FACTURA SERVICII VETERINARE", ln=True, align="C")
    pdf.ln(10)

    # Date Furnizor
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Furnizor: Puppy Vet Clinic", ln=True)
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, "Str. Exemplului nr. 10, Bucuresti", ln=True)
    pdf.cell(0, 10, "CIF: RO12345678", ln=True)
    pdf.ln(10)

    # Date Client
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, f"Client: {plata.Nume} {plata.Prenume}", ln=True)
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Adresa: {plata.Adresa}", ln=True)
    pdf.ln(20)

    # Tabel Servicii
    pdf.set_font("Arial", "B", 12)
    pdf.cell(130, 10, "Descriere Serviciu", border=1)
    pdf.cell(60, 10, "Pret (RON)", border=1, ln=True, align="C")

    pdf.set_font("Arial", "", 12)
    pdf.cell(130, 10, f"{plata.Descriere}", border=1)
    pdf.cell(60, 10, f"{plata.Suma:.2f}", border=1, ln=True, align="C")

    # Total
    pdf.ln(5)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(130, 10, "TOTAL DE PLATA:", align="R")
    pdf.cell(60, 10, f"{plata.Suma:.2f} RON", border=1, align="C", ln=True)

    # Footer
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
    """Injectează notificările în toate paginile (clopoțelul de sus)"""
    if "user_id" not in fl.session:
        return dict(notificari=[], nr_notificari=0)

    notificari = []
    try:
        # 1. Programări în așteptare
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

        # 2. Programări confirmate AZI
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


@app.context_processor
def inject_user_data():
    """Injectează datele userului (Nume, Poză) în toate paginile"""
    if "user_id" in fl.session:
        # Încercăm fallback pe sesiune dacă nu vrem query la fiecare refresh
        # Dar pentru siguranță și update instant la poză, facem query
        try:
            sql = "SELECT Username, Email, Profile_Pic FROM USER_ACCOUNT WHERE Id_user = :uid"
            res = db.session.execute(
                text(sql), {"uid": fl.session["user_id"]}
            ).fetchone()

            if res:
                pic = (
                    res[2]
                    if res[2]
                    else fl.url_for("static", filename="img/default_avatar.jpg")
                )
                return dict(
                    user={
                        "username": res[0],
                        "email": res[1],
                        "profile_picture_url": pic,
                    }
                )
        except:
            pass

        # Fallback absolut
        return dict(
            user={
                "username": fl.session.get("username", "User"),
                "profile_picture_url": fl.session.get(
                    "profile_pic",
                    fl.url_for("static", filename="img/default_avatar.jpg"),
                ),
            }
        )

    return dict(user=None)


if __name__ == "__main__":
    app.run(debug=True)
