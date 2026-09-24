# Bismilla Biryani — SQLite Database Version

This version connects the existing HTML app to a Node.js + Express + SQLite backend.

## What is stored

### users
- name
- email
- mobile
- password hash (NOT plaintext password)
- address
- account creation time

### login_events
Every successful login creates:
- user_id
- login_time

### payments
Every confirmed payment creates:
- user_id
- order_id
- amount
- payment method
- payment status
- order status
- ordered items
- delivery address
- payment time

### sessions
A login creates a temporary session token so the browser can remain logged in.

## Run

Open a terminal:

```bash
cd server
npm install
npm start
```

The API runs on:

http://localhost:5000

Then open:

`client/bismilla_biryani_app.html`

For the browser to call the API from the local file, Chrome may restrict some requests depending on its security settings. For a clean setup, serve the client through a local web server such as VS Code Live Server or move the HTML into a small Express static folder.

## Database

After the first server start, this file is automatically created:

`server/bismilla.db`

Do not commit `bismilla.db` or production secrets to GitHub.

## Security

Passwords are hashed with bcrypt. The database does not store the user's plaintext password.

The `/api/admin/activity` endpoint is intentionally a development report endpoint. Before deploying publicly, protect it with proper admin authentication/authorization.

## Exact GPS location

The client now uses the browser/device Geolocation API with `enableHighAccuracy: true`, `maximumAge: 0`, and a 20-second timeout. It stores latitude, longitude, and GPS accuracy in SQLite and reverse-geocodes the coordinates into a readable delivery address.

For Chrome testing, run the client through `http://localhost` (for example VS Code Live Server) instead of opening the HTML with `file://`. When Chrome asks for location permission, choose **Allow** and make sure Windows/device Location is enabled.


## View Database Data

After starting the Node server, open `admin.html` through VS Code Live Server. It displays registered users, GPS latitude/longitude/accuracy, login history, and payment/order data from `server/bismilla.db`.

The dashboard uses the development endpoint `/api/admin/activity`. Before public deployment, protect this endpoint with proper admin authentication and authorization.


## Firebase Authentication setup

This version uses **Firebase Authentication (Email/Password)** for registration and login.
SQLite remains the application database for profile data, GPS/location, login history and orders.

### 1. Firebase Console
1. Create/open your Firebase project.
2. Go to **Authentication -> Sign-in method** and enable **Email/Password**.
3. Go to **Project settings -> Your apps -> Web app** and copy the Firebase web config.
4. Paste those values into `client/firebase-config.js`.
5. Go to **Project settings -> Service accounts -> Generate new private key**.
6. Keep the downloaded service-account JSON private.

### 2. Configure the Node server
Set the environment variable `GOOGLE_APPLICATION_CREDENTIALS` to the service-account JSON path.

Windows CMD example:
```bat
set GOOGLE_APPLICATION_CREDENTIALS=C:\path\to\serviceAccountKey.json
cd server
npm install
npm start
```

### 3. Run the app
Serve the project/client folder through a local web server (do not open the HTML with `file://`).
The Node API runs on `http://localhost:5000`.

### What is stored where?
- **Firebase Authentication:** email/password account and Firebase UID.
- **SQLite (`server/bismilla.db`):** name, mobile, address, GPS, login events, payments/orders.
- **Firebase Admin SDK:** verifies Firebase ID tokens on the Node server.

Do not upload `serviceAccountKey.json` to GitHub.
