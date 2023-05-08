require("./utils.js");

const express = require('express');

const session = require('express-session');

const MongoStore = require('connect-mongo');

require('dotenv').config();

const bcrypt = require('bcrypt');

const Joi = require("joi");

const app = express();

const port = process.env.PORT || 3020;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

const saltRounds = 12;

const expireTime = 1 * 60 * 60 * 1000;

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
});

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore,
	saveUninitialized: false, 
	resave: true
}
));

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}


function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}

app.get('/', (req,res) => { //good
    if(req.session.authenticated){
        var name = req.session.name;
        res.render("index-member", {name: name});
    } else {
        res.render("index");
    }
});

app.get('/nosql-injection', async (req,res) => { //good
	var name = req.query.name;

	if (!name) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+name);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(name);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({name: name}).project({name: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${name}</h1>`);
});

app.get('/signup', (req,res) => { //good
    res.render("signup");
});

app.post('/submitUser', async(req, res) => { //good
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
		{
			name: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
			password: Joi.string().max(20).required()
		});

	const validationResult = schema.validate({name, email, password});
	if (validationResult.error != null) {
       var message = validationResult.error.details[0].message;
       res.render("invalid-signup", {message: message});
	   return;
   }

   var hashedPassword = await bcrypt.hash(password, saltRounds);

   await userCollection.insertOne({name: name, email: email, password: hashedPassword, user_type: "user"});
   console.log("inserted user");


   req.session.authenticated = true;
   req.session.name = req.body.name;
   res.redirect("/members");

   return;

});

app.get('/login', (req,res) => { //good
    if(!req.session.authenticated){
        res.render("login");
    } else {
        res.redirect("members");
    }
});

app.post('/loggingin', async (req,res) => { //done
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({email: email}).project({email: 1, password: 1, _id: 1, name: 1, user_type: 1}).toArray();

	if (result.length != 1) { //if user doesnt exist
        res.render("incorrect-login");
		return;
	}

	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.email = email;
        req.session.name = result[0].name;
        req.session.user_type = result[0].user_type;
        console.log(result[0].user_type);
		req.session.cookie.maxAge = expireTime;

        var name = req.session.name;
		res.redirect('/members');
		return;
	}
	else {
        res.render("incorrect-login");
        return;
	}
});

app.get('/members', (req,res) => { //good
    if(!req.session.authenticated) {
        res.render("index");
    } else {
        var name = req.session.name;
        res.render("members", {name: name});
    }
});

app.get('/logout', (req,res) => { //good
	req.session.destroy();
    res.redirect("/");
});

app.get('/cat/:id', (req,res) => { //good
    var cat = req.params.id;

    if(cat == 1){
        res.redirect("/hop.gif");
    } else if (cat == 2){
        res.redirect("/mad.gif");
    } else if(cat == 3){
        res.redirect("/team.gif");
    }
});

app.post('/promote/:id', async (req,res) => { //good
    var name = req.params.id;

    await userCollection.updateOne({name: name}, {$set: {user_type: 'admin'}});
    res.redirect("/admin");
});

app.post('/demote/:id', async (req,res) => { //good
    var name = req.params.id;

    await userCollection.updateOne({name: name}, {$set: {user_type: 'user'}});
    res.redirect("/admin");
});


app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({name: 1, _id: 1, user_type: 1}).toArray();
 
    res.render("admin", {user: result});
});

app.use(express.static(__dirname + "/public"));


app.get("*", (req,res) => {
    res.status(404);
    res.render("404");
});

app.listen(port, () => {
    console.log("Listening on port " + port);
});