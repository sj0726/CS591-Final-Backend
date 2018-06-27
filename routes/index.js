const express = require('express');
const router = express.Router();
const request = require("request-promise");
const tweets = require


/* GET home page. */
router.post('/', function(req, res, next) {
    const text = req.body.q
    const targetLang = req.body.target

    const request = require("request");

    const options = { method: 'POST',
        url: 'https://translation.googleapis.com/language/translate/v2',
        qs: { key: 'AIzaSyBI-GW7GH5hHmz_41BcGcPv_dpGGrLoGEQ' },
        headers:
            { 'Postman-Token': '337e4abc-14b1-476f-a2bf-8058fb44481f',
                'Cache-Control': 'no-cache',
                'Content-Type': 'application/x-www-form-urlencoded' },
        form: { 'q': text, target: targetLang } };

    request(options, function (error, response, body) {
        if (error) throw new Error(error);
        console.log(body)

        let result = JSON.parse(body)
        let result2 = result.data.translations[0]
        console.log(result2)
        res.json({'Translated Text': result2.translatedText, 'Detected Language': result2.detectedSourceLanguage})
    });
})

module.exports = router;
