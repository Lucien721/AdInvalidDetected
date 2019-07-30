pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;

contract Migrations {

  struct Click {
    uint userIP;
    uint cost;
    uint proof;
    uint time;
  }

  address private adnetwork;
  address private advertiser;

  mapping (uint=>uint) IPtoNumbers;
  mapping (address=>uint) adMoney;

  Click[] public clicks;
  Click[] public fakeClicks;

  uint public cash = 0;
  uint public hashnum;
  uint public NumHash;

  function balanceOf(address _owner) public view returns (uint) {
    return adMoney[_owner];
  }

  function initAccount(address _adnet, address _adver) public {
    adnetwork = _adnet;
    advertiser = _adver;
    adMoney[adnetwork] = 10000;
  }

  modifier insure() {
    require(balanceOf(adnetwork) > 2 * 1000);
    _;
  }

  function Processing(uint[] memory _userIP, uint[] memory _cost, uint[] memory _proof,uint[] memory _time) public {
    for(uint i = 0; i < _userIP.length; i++){
      clicks.push(Click(_userIP[i], _cost[i], _proof[i], _time[i]));
      IPtoNumbers[_userIP[i]] += 1;
    }
  }

  function test(uint _Ktimes) public {
    for(uint i = 0; i < clicks.length - 1; i++){
      for(uint j = i + 1; j < clicks.length; j++){
        if(clicks[i].proof == clicks[j].proof){
          fakeClicks.push(clicks[j]);
          IPtoNumbers[clicks[j].userIP] -= 1;
          clicks[j] = Click(0,0,0,0);
        }
      }
    }
    for(uint k = 0; k < clicks.length - 1; k++ ){
      if(IPtoNumbers[clicks[k].userIP] > _Ktimes){
        uint count = IPtoNumbers[clicks[k].userIP] - _Ktimes;
        for(uint m = k + 1; m < clicks.length; m++){
          if(clicks[m].userIP == clicks[k].userIP){
            fakeClicks.push(clicks[m]);
            IPtoNumbers[clicks[m].userIP] -= 1;
            clicks[m] = Click(0,0,0,0);
          }
        }
      }
    }
    for(uint t = 0; t < fakeClicks.length; t++) {
      cash += fakeClicks[t].cost;
    }
    hashnum = keccak256("fakeClicks");
  }

  event CostCalculate(bool isSuccess, string message);
  function costCalculate(bool _succ) public insure(){
    NumHash = hashnum;
    adMoney[advertiser] += cash;
    adMoney[adnetwork] -= cash;
    _succ = true;
    emit CostCalculate(_succ, "Get the money back！");
  }
}
