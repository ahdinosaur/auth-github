var resource = require('resource'),
    logger = resource.logger,
    http = resource.use('http'),
    config = resource.use('config')['auth-github'],
    auth = resource.use('auth'),
    user = resource.use('user'),
    github = resource.define('auth-github');

github.schema.description = "for integrating github authentication";

github.persist('memory');

// .start() convention
function start(options, callback) {
  var async = require('async');
  //
  // setup auth provider
  //
  async.parallel([
    // setup .view convention
    function(callback) {
      var view = resource.use('view');
      view.create({ path: __dirname + '/view' }, function(err, _view) {
          if (err) { return callback(err); }
          github.view = _view;
          return callback(null);
      });
    },
    // start auth with github
    function(callback) {
      auth.start({provider: github}, callback);
    },
    // use auth strategy of provider
    function(callback) {
      github.strategy(function(err, strategy) {
        if (err) { return callback(err); }
        auth.use(strategy, callback);
      });
    },
    // use route of provider
    function(callback) {
      github.routes({}, callback);
    }],
  function(err, results) {
    return callback(err);
  });
}
github.method('start', start, {
  description: "starts github"
});

github.property('accessToken', {
  description: 'access token of github auth'
});

github.property('refreshToken', {
  description: 'access token of github auth'
});

github.property('profile', {
  description: 'profile of github auth'
});

function strategy(callback) {
  var GitHubStrategy = require('passport-github').Strategy;
  // Use the GitHubStrategy within Passport.
  //   Strategies in Passport require a `verify` function, which accept
  //   credentials (in this case, an accessToken, refreshToken, and GitHub
  //   profile), and invoke a callback with a user object.
  callback(null, new GitHubStrategy({
    clientID: config.clientID,
    clientSecret: config.clientSecret,
    callbackURL: "http://localhost:8888/auth/github/callback",
    passReqToCallback: true
  },
  function(req, accessToken, refreshToken, profile, done) {
    // asynchronous verification, for effect...
    process.nextTick(function () {
      if (!req.user) {
        logger.info('user is not logged in, authorizing with github');
        github.get(profile.id, function(err, _github) {
          if (err && (err.message === profile.id + " not found")) {
            logger.info("profile.id not found. creating new github");
            github.create({id: profile.id}, function(err, _github) {
              if (err) { return done(err); }
              logger.info("new github with id", _github.id, "created");
              logger.info("since new github, creating new user");
              user.create({github: _github.id}, function(err, _user) {
                if (err) { return done(err); }
                logger.info("new user with id", _user.id, "created");
                logger.info("new user object", JSON.stringify(_user));
                return done(null, _user);
              });
            });
          } else if (err) {
            return done(err);
          } else {
            logger.info("profile.id found, using associated github");
            user.find({github: _github.id}, function(err, _users) {
              if (err) { return done(err); }
              if (_users.length > 1) {
                // TODO merge multiple users with same github into one
                return done(null, _user[0]);
              }
            });
          }
        });
      } else {
        logger.info('user is logged in, associating github with user');
        var _user = req.user;
        github.get(profile.id, function(err, _github) {
          if (err && (err.message === profile.id + " not found")) {
            logger.info("profile.id not found. creating new github");
            github.create({id: profile.id}, function(err, _github) {
              logger.info("new github with id", _github.id, "created");
              if (err) { return done(err); }
              // associate new github with user
              _user['github'] = _github.id;
              // preserve the login state by returning the existing user
              done(null, _user);
            });
          } else if (err) {
            return done(err);
          } else {
            logger.info("profile.id found. using existing github");
            // associate new github with user
            _user['github'] = _github.id;
            // preserve the login state by returning the existing user
            done(null, _user);
          }
        });
      }
    });
  }));
}
github.method('strategy', strategy, {
  description: 'return GitHub strategy'
});

function routes(options, callback) {
  var authOrAuthz = function(req, res, next) {
    if (!req.isAuthenticated()) {
      auth.authenticate('github', {
        successRedirect: '/',
        failureRedirect: '/'
      })(req, res, next);
    } else {
      auth.authorize('github')(req, res, next);
    }
  };
  http.app.get('/auth/github', authOrAuthz);
  http.app.get('/auth/github/callback', authOrAuthz);
  callback(null);
}
github.method('routes', routes, {
  description: 'sets routes for github in app'
});

github.dependencies = {
  'passport-github': '*'
};
github.license = 'MIT';
exports['auth-github'] = github;
