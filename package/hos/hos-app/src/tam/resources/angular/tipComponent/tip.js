
(function () {
    angular.module("tipService", [ ])

        .directive('tip', function ($translate) {
            return {
                restrict: 'ECAM',
                templateUrl: '../resources/angular/tipComponent/tip.html',
                replace: true,
                scope: {
                    myData: '='
                },
                link: function (scope, element, attrs) {

                    console.log(scope.myData);
                    scope.innerMethod = function () {
                        scope.myData.show = false;
                        //scope.$parent.$parent.message.show = false;
                    };
                }
            };
        })
        .provider('destroyInfoMsg', function () {
            return {
                $get: function ($timeout) {
                    return function ($scope, content, show, time) {
                        $scope.message.mytype = 'info';
                        $scope.message.show = true;
                        $scope.message.content = content;
                        $timeout(function () {
                            $scope.$apply(function () {
                                $scope.message.show = false;
                                $scope.message.content = '';
                            });
                        }, time);
                    }
                }
            }
        })
        .provider('destroyErrorMsg', function () {
            return {
                $get: function ($timeout) {
                    return function ($scope, content, show, time) {
                        $scope.message.mytype = 'error';
                        $scope.message.show = true;
                        $scope.message.content = content;
                        $timeout(function () {
                            $scope.$apply(function () {
                                $scope.message.show = false;
                                $scope.message.content = '';
                            });
                        }, time);
                    }
                }
            }
        });
}).call(this);
