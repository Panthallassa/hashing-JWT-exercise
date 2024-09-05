const express = require("express");
const User = require("../models/user");
const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../config");
const ExpressError = require("../expressError");

const router = new express.Router();

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post("/login", async function (req, res, next) {
	try {
		const { username, password } = req.body;
		const isValid = await User.authenticate(
			username,
			password
		);

		if (isValid) {
			await User.updateLoginTimestamp(username);
			const token = jwt.sign({ username }, SECRET_KEY);
			return res.json({ token });
		} else {
			throw new ExpressError(
				"Invalid username/password",
				400
			);
		}
	} catch (err) {
		return next(err);
	}
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post("/register", async function (req, res, next) {
	try {
		const { username } = await User.register(req.body);
		await User.updateLoginTimestamp(username);
		const token = jwt.sign({ username }, SECRET_KEY);
		return res.json({ token });
	} catch (err) {
		return next(err);
	}
});

module.exports = router;
