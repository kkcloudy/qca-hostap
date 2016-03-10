(function () {
    var module;

    module = angular.module('angularBootstrapDrowup', []);

    module.directive('dropdownSingle',function ($translate) {
            return {
                restrict: 'E',
                templateUrl:'../resources/angular/dropdownSingleselect/dropdown_single_template.html',
                replace: true,
                scope: {
                    inputHeight:'=',
                    inputWidth:'=',
                    listWidth:'=',
                    initData: '=',
                    initSelect:'=',
                    monitorAttr:'@',
                    editAble:'@'
                },
                link: function (scope, element, attrs) {

                    if(angular.isUndefined(scope.monitorAttr )){
                        scope.monitorAttr = 'selectValue';
                    }
                    if(angular.isUndefined(scope.editAble )){
                        scope.editAble = true;
                    }
                    /*
                      传入的initData可以是对象列表，列表中显示的为attribute值
                      或者可以传入数据即可
                     */
                    scope.option = {
                        stringList:false,
                        objectList:false,
                        mymodel:''
                    };
                    if(scope.initData.length !== 0 && angular.isString(scope.initData[0])){
                           scope.option.stringList = true;
                    }else if(scope.initData.length !== 0 && angular.isObject(scope.initData[0])){
                           scope.option.objectList = true;
                    }else{
                           scope.option.stringList = true;
                    }

                    // 为了处理国际化带来的问题
                    scope.setMValue = function () {
                         //console.log("xxxxxx"+scope.option.mymodel);
                         if($translate.instant(scope.option.mymodel) === scope.option.mymodel){
                             scope.initSelect[scope.monitorAttr] = scope.option.mymodel;
                         }
                    };

                    scope.setValue = function (item) {
                        //console.log("进行了触发的行为");
                        scope.setFlag();
                        scope.initSelect[scope.monitorAttr] = item;
                    };
                    // 当按编辑按钮时，将默认的选择项进行国际化转化
                    scope.$watch(function () {
                        return  scope.initSelect[scope.monitorAttr];
                    }, function () {
                        scope.option.mymodel = $translate.instant(scope.initSelect[scope.monitorAttr]);
                    });

                    // 控制下拉列表的显示与隐藏
                    scope.isActive = false;
                    scope.setFlag = function () {
                        scope.isActive = !scope.isActive;
                    };
                    scope.controlList = {width:scope.listWidth};
                    scope.controlInput = {height:scope.inputHeight,width:scope.inputWidth};
                    scope.controlA = {height:scope.inputHeight,width:'40px'};

                }
            }
        }
    );

}).call(this);
