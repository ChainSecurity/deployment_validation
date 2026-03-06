contract FailingChild {
    constructor() {
        revert();
    }

    uint256 public very_important = 42;
}

contract WorkingChild {
    constructor() {
        uint256 index;
        if (gasleft() > 1) {
            index = 4;
        }
        some_map[index] = 5;
    }

    uint256 public very_important = 42;

    uint256 public some_function = 23;

    mapping(uint256 => uint256) public some_map;
}

contract SomeDeployer {
    constructor() {
        // Do some stuff in the constructor
        try new FailingChild() {} catch (bytes memory) {}
        try new FailingChild() {} catch (bytes memory) {}
        try new WorkingChild() {} catch (bytes memory) {}
    }

    function f() external {
        // succeed in the middle of failures
        try new FailingChild() {} catch (bytes memory) {}
        try new WorkingChild() {} catch (bytes memory) {}
        try new FailingChild() {} catch (bytes memory) {}
    }

    function g() external {
        // first succeed then fail
        try new WorkingChild() {} catch (bytes memory) {}
        try new FailingChild() {} catch (bytes memory) {}
        try new FailingChild() {} catch (bytes memory) {}
    }

    function dummy() external {}
}
