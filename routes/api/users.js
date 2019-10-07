const express = require('express');
const router = express.Router(); 
const { check, validationResult } = require('express-validator/check');
const User = require('../../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); 
const config = require('config')
// @route   POST api/users
// @desc    Register user
// @access  Public 
router.post('/', [
    check('name', 'Name is required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Please enter password with 6 or more characters').isLength({ min:6 })
] ,
   async (req, res) => { 
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array()})
    }

    const { name, email, password } = req.body; 

    // See if user exists

    try {
        //This is MongoDB documentation
        let user = await User.findOne({ email });

        // See if user exists 
        if(user) {
          return  res.status(400).json({ errors: [ { msg: 'User already exists' }]});
        }

        user = new User({
            name,
            email,
            password
        });

        // Encrypt password
        const salt = await bcrypt.genSalt(10);

        user.password = await bcrypt.hash(password, salt);

        await user.save();
        
        const payload = {
            user: {
                id: user.id
            }
        }

        jwt.sign(payload, config.get('jwtSecret'), { expiresIn:360000 }, (err, token) => {
            if(err) throw err;
            res.json({ token });
        } )
        

    } catch(err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
}) 

module.exports = router; 