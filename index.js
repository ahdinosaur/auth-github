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

github.property('credentials', {
  description: 'github credentials',
  type: 'object',
  properties: {
    accessToken: {
      description: 'access token of github auth',
      type: 'string',
      required: true
    },
    refreshToken: {
      description: 'refresh token of github auth',
      type: 'string',
      required: false
    }
  }
});

github.property('profile', {
  description: 'profile of github auth',
  type: 'object'
});

function strategy(callback) {
  var GitHubStrategy = require('passport-github').Strategy,
      async = require('async');
  // Use the GitHubStrategy within Passport.
  //   Strategies in Passport require a `verify` function, which accept
  //   credentials (in this case, an accessToken, refreshToken, and GitHub
  //   profile), and invoke a callback with a user object.
  return callback(null, new GitHubStrategy({
    clientID: config.clientID,
    clientSecret: config.clientSecret,
    callbackURL: "http://localhost:8888/auth/github/callback",
    passReqToCallback: true
  },
  function(req, accessToken, refreshToken, profile, done) {
    // asynchronous verification, for effect...
    process.nextTick(function () {
      async.waterfall([
        // get github instance, or create if not already exist
        function(callback) {
          github.get(profile.id, function(err, _github) {
            if (err && (err.message === profile.id + " not found")) {
              logger.info("github id", profile.id, "not found. creating new github");
              github.create({
                id: profile.id,
                credentials: {
                  accessToken: accessToken,
                  refreshToken: refreshToken
                },
                profile: profile
              }, callback);
            } else if (err) {
              return callback(err);
            } else {
              logger.info("github id ", _github.id, "found");
              github.update({
                id: profile.id,
                credentials: {
                  accessToken: accessToken,
                  refreshToken: refreshToken
                },
                profile: profile
              }, callback);
            }
          });
        },
        // log github object
        function(_github, callback) {
          logger.info("github object", JSON.stringify(_github));
          return callback(null, _github);
        },
        // associate github with user auth
        function(_github, callback) {
          var _user = req.user;
          if (!_user) {
            logger.info('user is not logged in');
            async.waterfall([
              // find auth instances with github id, or create none exist
              function(callback) {
                auth.find({github: _github.id}, function(err, _auths) {
                  if (err) { return callback(err); }
                  else if (_auths.length > 1) {
                    logger.info("multiple auths with same github id found!");
                    // TODO merge multiple auths with same github into one
                    return callback(null, _auth[0]);
                  } else if (_auths.length === 0) {
                    logger.info("github id", _github.id, "not found in any auth. creating new auth");
                    auth.create({github: _github.id}, callback);
                  } else {
                    logger.info("using existing auth", _auths[0].id);
                    return callback(null, _auths[0]);
                  }
                });
              },
              // log auth object
              function(_auth, callback) {
                logger.info("auth object", JSON.stringify(_auth));
                return callback(null, _auth);
              },
              // find user instance with auth id, or create if none exist
              function(_auth, callback) {
                logger.info("getting user with auth id");
                user.get(_auth.id, function(err, _user) {
                  if (err && (err.message === _auth.id + " not found")) {
                    logger.info("user id", _auth.id, "not found. creating new user");
                    user.create({id: _auth.id}, callback);
                  } else if (err) {
                    return callback(err);
                  } else {
                    logger.info("user id ", _user.id, "found");
                    return callback(null, _user);
                  }
                });
              }],
              // return user object to top waterfall
              callback);
          } else {
            logger.info('user is logged in');
            auth.get(_user.id, function(err, _auth) {
              // TODO check for collisions here
              // associate github with auth
              _auth['github'] = _github.id;
              // save auth instance
              _auth.save(function(err, _auth) {
                if (err) { return callback(err); }
                // log auth object
                logger.info("auth object", JSON.stringify(_auth));
                // return user object to top waterfall
                return callback(null, _user);
              });
            });
          }
        }],
        // end top waterfall
        done);
    });
  }));
}
github.method('strategy', strategy, {
  description: 'return GitHub strategy'
});

function routes(options, callback) {
  http.app.get('/auth/github',
    auth.authenticate('github'));
  http.app.get('/auth/github/callback',
    auth.authenticate('github', { failureRedirect: '/' }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/');
    });
  return callback(null);
}
github.method('routes', routes, {
  description: 'sets routes for github in app'
});

github.dependencies = {
  'passport-github': '*'
};
github.license = 'MIT';
exports['auth-github'] = github;
