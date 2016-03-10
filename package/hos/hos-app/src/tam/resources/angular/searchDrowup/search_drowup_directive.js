(function () {
    var module;

    module = angular.module('angularBootstrapSearchdrowup', []);

    module.directive('searchDrowup',function () {
        return {
            restrict: 'E',   // default value
            templateUrl:'../resources/angular/searchDrowup/search_drowup_template.html',
            replace: true,
            scope: {
                initData: '=',
                initSelect:'=',
                onSearch:'&'
            },
            link: function (scope, element, attrs) {

                if (attrs.drowupText == null) {
                     scope.initSelect.drowupText = scope.initData[0]
                }

                scope.set_drowuptext = function (name) {
                    scope.initSelect.drowupText = name;
                };

                scope._search = function () {
                    //console.log(scope.initSelect.drowupText+"/"+scope.initSelect.searchText);
                    scope.onSearch();
                };
                // 重置
                scope._reset = function () {
                    scope.initSelect.searchText = "";
                    scope.onSearch();
                }
            }}
    }
    );



}).call(this);
