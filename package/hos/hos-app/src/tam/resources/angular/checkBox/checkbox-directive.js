(function () {
    var module;

    module = angular.module('angularBootstrapCheckbox', []);

    module.directive('checkbox',function () {
            return {
                restrict: 'E',
                templateUrl:'../resources/angular/checkBox/checkbox-template.html',
                replace: true,
                scope: {
                    selectValue: '=',
                    onSelect:'&'
                },
                link: function (scope, element, attrs) {

                    scope.initData = {
                        mystyle :'check-box',
                        selectState:false
                    };

                    if(scope.selectValue === undefined){
                        scope.selectValue = false;
                    }else if(scope.selectValue === true){
                        scope.selectValue = true;
                        scope.initData.mystyle = 'check-box checkedBox';
                        scope.initData.selectState = true;
                    }

                    scope.set_selectbox = function () {
                        if(scope.initData.selectState){
                            scope.initData.mystyle = 'check-box';
                            scope.initData.selectState = false;
                        }else{
                            scope.initData.mystyle = 'check-box checkedBox';
                            scope.initData.selectState = true;
                        }
                        scope.selectValue = scope.initData.selectState;
                        scope.onSelect();
                    }

                }}
        }
    );

}).call(this);
