from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from datetime import timedelta
import os

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "June2306$")

# Database config
app.config['SQLALCHEMY_DATABASE_URI'] = (
    'postgresql://go_electric_43j8_user:UbXq2tWaAYkJ3hkSnPoAGinfox3gAuzb'
    '@dpg-d2veugbipnbc73cjuppg-a.oregon-postgres.render.com/go_electric_43j8'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Google OAuth settings
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # ⚠️ Only for dev
GOOGLE_CLIENT_SECRETS_FILE = "C:/Users/ADMIN/Go electric/Client Secret/client_secret_214552763992-t4if66jpg982ldu1jm9l0sc1tnhd9ut0.apps.googleusercontent.com.json" 
SCOPES = [
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email',
    'openid'
]

# ------------------ USER MODEL ------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    full_name = db.Column(db.String(150), nullable=True)
    current_location = db.Column(db.String(150), nullable=True)
    google_token = db.Column(db.String(255), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password) if self.password_hash else False


# ------------------ PRODUCT LIST ------------------ 

products = [
    # Generators
    {"id": 1, "name": "Honda EU2200i", "price": 1299, "image": "small gen.png", "description": "2200W Portable Inverter Generator"},
    {"id": 2, "name": "Generac Guardian 22kW", "price": 4999, "image": "big Gen.png", "description": "22kW Standby Generator with Wi-Fi"},
    {"id": 3, "name": "Westinghouse Wgen7500", "price": 899, "image": "gen 3.png", "description": "7500W Portable Generator"},
    {"id": 4, "name": "Champion 3400", "price": 3799, "image": "yellow gen.png", "description": "14kW Standby Generator"},
    {"id": 5, "name": "Kohler 14RESAL", "price": 699, "image": "kohler.png", "description": "3400W Dual Fuel Generator"},
    {"id": 6, "name": "Predator 3500", "price": 799, "image": "799.png", "description": "3500W Super Quiet Inverter Generator"},
    {"id": 7, "name": "Honda EU2200i", "price": 1199, "image": "honda.png", "description": "2200W Portable Inverter Generator"},
    {"id": 8, "name": "Generac Guardian 22kW", "price": 4899, "image": "22kw.png", "description": "22kW Standby Generator with Wi-Fi"},
    {"id": 9, "name": "Yamaha EF2200iS", "price": 1799, "image": "yamaha.png", "description": "2200W Portable Inverter Generator"},
    {"id": 10, "name": "Champion 7500W", "price": 899, "image": "Champion.png", "description": "7500W Portable Generator"},
    {"id": 11, "name": "EcoFlow Delta Pro", "price": 3599, "image": "ecoflow.png", "description": "3600Wh Solar/AC Portable"},
    {"id": 12, "name": "Honda EUi1000", "price": 699, "image": "Super quiet.png", "description": "1000W gasoline Inverter"},

    # Boats
    {"id": 13, "name": "Thunder E sport", "price": 125000, "image": "Thunder E sport.png", "description": "28ft electric sport boat"},
    {"id": 14, "name": "Silent fisher", "price": 85000, "image": "silent fisher.png", "description": "22ft electric fishing boat"},
    {"id": 15, "name": "Ecoboatmini", "price": 45000, "image": "Ecoboatmini.png", "description": "16ft electric recreation boat"},
    {"id": 16, "name": "Family Cruiser", "price": 95000, "image": "family cruiser.png", "description": "32ft Electric pontoon boat"},
    {"id": 17, "name": "Oceanic Elite", "price": 1200000, "image": "Oceanic elite.png", "description": "65ft Electric mega yacht"},

    # Aircraft
    {"id": 18, "name": "Cargofly Pro", "price": 2100000, "image": "Cargofly pro.png", "description": "Heavy-duty cargo aircraft for commercial deliveries"},
    {"id": 19, "name": "Luxair Elite", "price": 1800000, "image": "luxair elite.png", "description": "Premium passenger aircraft with advanced features"},
    {"id": 20, "name": "Urban Hopper", "price": 450500, "image": "airhopper.png", "description": "Compact urban mobility solution for short-distance travel"},
    {"id": 21, "name": "Jet", "price": 3799, "image": "Jet.png", "description": "Military-grade electric aircraft for defense operations"},
    {"id": 22, "name": "Private Jet", "price": 3000000, "image": "private console.png", "description": "Luxury private jet for executive travel"},

    # Washing Machines
    {"id": 23, "name": "Electrowash Pro 5000", "price": 42500, "image": "washer1.png", "description": "Heavy-duty industrial washer with 50Kg capacity and advanced electrical controls"},
    {"id": 24, "name": "Inducluean Compact 2500", "price": 28900, "image": "washer2.png", "description": "Compact and efficient washer with advanced features"},
    {"id": 25, "name": "Power wash Pro max 10000", "price": 89500, "image": "washer3.png", "description": "Maximum capacity industrial washer for larger scale operations with small controls"},
    {"id": 26, "name": "TechWash Eco 3500", "price": 3799, "image": "washer4.png", "description": "Energy efficient washing machine with advanced features"},
    {"id": 27, "name": "Electro wash smart 7500", "price": 67800, "image": "washer5.png", "description": "AI-powered washing cycles with remote monitoring and 75kg capacity"},
    {"id": 28, "name": "Induclean rapid 4000", "price": 67800, "image": "washer6.png", "description": "High-speed washing with 40kg capacity for quick turnaround operations"},
]

# ------------------ ROUTES ------------------
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/apply')
def apply():
    return render_template('login.html')


@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        full_name = request.form.get('full_name')
        current_location = request.form.get('current_location')
        password = request.form.get('password')

        if not email or not password:
            flash("Email and password required", "warning")
            return render_template('sign_up.html')

        if User.query.filter_by(email=email).first():
            flash("User already exists. Please log in.", "warning")
            return redirect(url_for('login'))

        try:
            new_user = User(email=email, full_name=full_name, current_location=current_location)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash("Signup successful! Please log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            print(e)
            flash("Error occurred. Try again.", "danger")
            return render_template('sign_up.html')

    return render_template('sign_up.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash("Please fill in both fields", "warning")
            return render_template('login.html')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['full_name'] = user.full_name
            session['email'] = user.email
            session['picture'] = None
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password", "danger")
            return render_template('login.html')

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to continue", "info")
        return redirect(url_for('login'))

    return render_template(
        'userpage.html',
        full_name=session.get('full_name', 'Guest'),
        profile_pic_url=session.get('picture')
    )


@app.route('/products')
def product_page():
    if 'user_id' not in session:
        flash("Please log in to view products", "info")
        return redirect(url_for('login'))

    return render_template(
        'product.html',
        full_name=session.get('full_name', 'Guest'),
        products=products
    )


# ------------------ CART SYSTEM ------------------
@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Login required"}), 401

    product_id = request.json.get("id")
    product = next((p for p in products if p["id"] == product_id), None)

    if not product:
        return jsonify({"status": "error", "message": "Product not found"}), 404

    if "cart" not in session:
        session["cart"] = []

    cart = session["cart"]

    for item in cart:
        if item["id"] == product_id:
            item["quantity"] += 1
            break
    else:
        product_copy = product.copy()
        product_copy["quantity"] = 1
        cart.append(product_copy)

    session["cart"] = cart
    session.modified = True
    total = sum(item["price"] * item["quantity"] for item in cart)
    return jsonify({"status": "success", "cart": cart, "total": total})


@app.route('/update_cart', methods=['POST'])
def update_cart():
    data = request.json
    product_id = data.get("id")
    action = data.get("action")

    cart = session.get("cart", [])
    updated_cart = []

    for item in cart:
        if item["id"] == product_id:
            if action == "increment":
                item["quantity"] += 1
            elif action == "decrement":
                item["quantity"] -= 1
            if item["quantity"] > 0:
                updated_cart.append(item)
            continue
        updated_cart.append(item)

    session["cart"] = updated_cart
    session.modified = True
    total = sum(item["price"] * item["quantity"] for item in updated_cart)
    return jsonify({"cart": updated_cart, "total": total})


@app.route('/remove_from_cart', methods=['POST'])
def remove_from_cart():
    data = request.json
    product_id = data.get("id")
    cart = session.get("cart", [])

    updated_cart = [item for item in cart if item["id"] != product_id]

    session["cart"] = updated_cart
    session.modified = True
    total = sum(item["price"] * item["quantity"] for item in updated_cart)
    return jsonify({"status": "success", "cart": updated_cart, "total": total})


@app.route('/cart')
def cart():
    if 'user_id' not in session:
        flash("Please log in to view your cart", "info")
        return redirect(url_for('login'))

    cart_items = session.get("cart", [])
    total = sum(item["price"] * item["quantity"] for item in cart_items)
    return render_template(
        'cart.html',
        full_name=session.get('full_name', 'Guest'),
        cart=cart_items,
        total=total
    )


# ------------------ OTHER ROUTES ------------------
@app.route('/vehicles')
def vehicles():
    return render_template('vehicles.html')


@app.route('/generator')
def generator():
    return render_template('generator.html')


@app.route('/homes')
def homes():
    return render_template('EVhomes.html')

@app.route('/about')
def about():
    return render_template('About.html')

@app.route('/Aircraft')
def aircraft():
    return render_template('Aircraft.html')

@app.route('/washing')
def washing():
    return render_template('Washing_machine.html')

@app.route('/boats')
def boats():
    return render_template('boats.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash("Please log in to view your profile", "info")
        return redirect(url_for('login'))

    # Try to get user from database
    user = User.query.filter_by(id=session['user_id']).first()
    if not user:
        flash("User not found", "danger")
        return redirect(url_for('login'))

    # Prepare user data for template
    user_info = {
        'full_name': user.full_name,
        'email': user.email,
        'current_location': user.current_location,
        'picture': session.get('picture')  # Google picture or None
    }

    return render_template('profile.html', user=user_info)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        return f"<h3>If {email} exists, a reset link has been sent.</h3>"
    return render_template('forgot_password.html')

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash("Please log in to edit your profile", "info")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        user.full_name = request.form.get('full_name')
        user.current_location = request.form.get('current_location')
        db.session.commit()

        # Update session
        session['full_name'] = user.full_name

        flash("Profile updated successfully!", "success")
        return redirect(url_for('profile'))

    return render_template('edit_profile.html', user=user)



# ------------------ GOOGLE LOGIN ------------------
@app.route('/login/google')
def login_with_google():
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for('google_callback', _external=True)
    )
    auth_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(auth_url)


@app.route('/login/google/callback')
def google_callback():
    try:
        flow = Flow.from_client_secrets_file(
            GOOGLE_CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=url_for('google_callback', _external=True)
        )
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        id_info = id_token.verify_oauth2_token(credentials.id_token, google_requests.Request())

        email = id_info.get("email")
        full_name = id_info.get("name")
        picture = id_info.get("picture")

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, full_name=full_name, google_token=credentials.token)
            db.session.add(user)
            db.session.commit()

        session['user_id'] = user.id
        session['full_name'] = full_name
        session['email'] = email
        session['picture'] = picture
        session.permanent = True
        app.permanent_session_lifetime = timedelta(days=7)

        return redirect(url_for('dashboard'))

    except Exception as e:
        print("Google login error:", e)
        flash("An error occurred during Google login. Try again.", "danger")
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ------------------ MAIN ------------------
if __name__ == '__main__':
    app.run(debug=True)
