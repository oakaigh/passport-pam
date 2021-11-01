import * as process from 'process';

import * as express from 'express';
import * as passport from 'passport';

import * as passport_http from 'passport-http';
import * as passport_pam from '../lib';


const PAMStrategy = passport_pam.Strategy(passport_http.BasicStrategy);

passport.use('pam',
    new PAMStrategy(
        {},
        {
            serviceName: 'login'
        },
        (_req, username, _password, authenticated, done) => {
            done(null, authenticated ? username : false);
        }
    )
);

const app = express();

app.use(passport.initialize());
app.use(passport.authenticate('pam', { session: false }));
app.get('/',
    (req, res) => {
        res.json(req.user);
    }
);

const port: number = parseInt(process.env['SERVER_PORT']) || 8080;
const hostname: string = process.env['SERVER_ADDR'] || 'localhost';
const backlog: number = parseInt(process.env['SERVER_BACKLOG']) || 1;

app.listen(port, hostname, backlog, () => {
    console.log('listening on', port, hostname, 'backlog', backlog);
});
