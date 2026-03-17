let userController = require('../controllers/users')
let jwt = require('jsonwebtoken')
let fs = require('fs')
let path = require('path')

const publicKey = fs.readFileSync(path.join(__dirname, 'public_key.pem'))

module.exports = {
    CheckLogin: async function (req, res, next) {
        let key = req.headers.authorization;
        if (!key) {
            if (req.cookies.LOGIN_NNPTUD_S3) {
                key = req.cookies.LOGIN_NNPTUD_S3;
            } else {
                res.status(401).send("ban chua dang nhap")
                return;
            }

        }

        try {

            let result = jwt.verify(key, publicKey, { algorithms: ['RS256'] })
            if (result.exp * 1000 < Date.now()) {
                res.status(401).send("ban chua dang nhap")
                return;
            }
            let user = await userController.GetUserById(result.id);
            if (!user) {
                res.status(401).send("ban chua dang nhap")
                return;
            }
            req.user = user;
            next();
        } catch (error) {
            res.status(401).send("ban chua dang nhap")
            return;
        }

    }
}