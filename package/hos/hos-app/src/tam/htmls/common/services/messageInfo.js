
   angular.module("messageInfoService", [ ])

        .directive('messageInfo', function () {
            return {
                restrict: 'ECAM',
                templateUrl: 'common/message-info.html',
                replace: true,
                transclude: true,
                scope: {
                    myType: '@'
                },
                link: function (scope, element, attrs) {
                    if (attrs.myType == null) {
                        //console.log('===============');
                        scope.myType = "info";
                    }
                    console.log("==========" + scope.myType);
                    //console.log(scope.myType);
                    scope.innerMethod = function () {
                        scope.$parent.$parent.message.show = false;
                    };
                    //scope.msgType = scope.$parent.$parent.message.type;
                }
            };
        })
        .provider('destroyInfoMsg', function () {
            return {
                $get: function ($timeout, $rootScope) {
                    return function ($scope, content, show, time) {

                        $scope.message = {
                            mytype: 'info',
                            show: show,
                            content: content
                        };
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
                $get: function ($timeout, $rootScope) {
                    return function ($scope, content, show, time) {
                        $scope.message = {
                            mytype: 'error',
                            show: show,
                            content: content
                        };
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


