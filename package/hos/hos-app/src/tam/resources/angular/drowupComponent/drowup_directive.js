(function () {
    var module;

    module = angular.module('angularBootstrapDrowup', []);

    module.directive('drowup',function () {
            return {
                restrict: 'E',
                templateUrl:'../resources/angular/drowupComponent/drowup_template.html',
                replace: true,
                scope: {
                    inputHeight:'=',
                    inputWidth:'=',
                    initData: '=',
                    initSelect:'=',
                    monitorAttr:'@'
                },
                link: function (scope, element, attrs) {

                    if(angular.isUndefined(scope.monitorAttr )){
                        scope.monitorAttr = 'selectValue';
                    }

                    scope.setValue = function (item) {
                        scope.setFlag();
                        scope.initSelect[scope.monitorAttr] = item;
                    };

                    // 控制下拉列表的显示与隐藏
                    scope.isActive = false;
                    scope.setFlag = function () {
                        scope.isActive = !scope.isActive;
                    };
                    scope.controlInput = {
                        height:scope.inputHeight,
                        width:scope.inputWidth
                    };
                    scope.controlA = {height:scope.inputHeight,width:'40px'};

                }
            }
        }
    );

}).call(this);
