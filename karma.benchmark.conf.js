
module.exports = function (config) {
  config.set({

    basePath: '',

    frameworks: [
      'browserify',
      'benchmark'
    ],

    files: [
      'benchmark/*.suite.js'
    ],

    preprocessors: {
      'benchmark/*.suite.js': [ 'browserify' ]
    },

    reporters: [
      'benchmark'
    ],

    port: 9876,

    colors: true,

    logLevel: config.LOG_INFO,

    autoWatch: true,

    browsers: ['Chrome', 'Firefox', 'Safari'],

    browserNoActivityTimeout: 100000,

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
