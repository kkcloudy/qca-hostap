(function () {
    var module;

    module = angular.module('angularBootstrapMzPanel', []);

    module.directive('mzPanel',function () {
            return {
                restrict: 'E',
                templateUrl:'../resources/angular/mzpanelComponent/mz_panel_template.html',
                replace: true,
                scope: {
                    initData: '=',
                    initSelect:'=',
                    onSearch:'&'
                },
                link: function (scope, element, attrs) {

                }}
        }
    );



}).call(this);
