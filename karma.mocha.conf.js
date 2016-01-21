
module.exports = function (config) {
  config.set({

    basePath: '',

    frameworks: [
      'browserify',
      'mocha'
    ],

    files: [
      'test/*.spec.js'
    ],

    preprocessors: {
      'test/*.spec.js': [ 'browserify' ]
    },

    reporters: [
      'progress'
    ],

    port: 9876,

    colors: true,

    logLevel: config.LOG_INFO,

    autoWatch: true,

    browsers: ['Chrome', 'Firefox', 'Safari'],

    singleRun: false,

    concurrency: Infinity,

    browserify: {
      debug: true,
      transform: [ 'brfs' ],
      configure: function(bundle) {
        bundle.on('prebundle', function() {
          bundle.external('foobar');
        });
      }
    }

  });
};
