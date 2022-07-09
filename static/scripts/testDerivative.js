function test(){
    let text=document.getElementById('thetext').value;
    let div=document.getElementById('display');
    let coeff=0, power=0;
    let variable='|';
    let ispower=false;
    let output="";
    let hit=false;
    let neg=false;
    let first=true;
    for(let i=0; i<text.length; i++){
        if(text[i]===' '||i==text.length-1){
            if(!hit){ 
                power=0;
                coeff=0;
                ispower=false;
                neg=false;
                continue; 
            }
            if(coeff===0) coeff=1;
            if(!ispower) power=1;
            coeff*=power;
            hit=false;
            power--;
            var tmp="";
            while(coeff!=0){
                tmp = tmp.concat((coeff%10).toString());
                coeff=~~(coeff/10);
            }
            let another="";
            for(let j=tmp.length-1; j>=0; --j){
                another=another.concat(tmp[j]);
            }
            if(neg){
                if(first){
                    output=output.concat("-");
                }
                else output = output.concat(" - ");
            } 
            else if(!first) output=output.concat(" + ");
            output = output.concat(another);
            if(power!=0) output = output.concat(variable);
            if(power!=1&&power!=0) {
                output = output.concat('^');
                output = output.concat(power.toString());
            }
            neg=false;
            coeff=0;
            ispower=false;
            power=0;
            first=false;
        }
        else if(text[i]==='^'){
            ispower=true;
        }
        else if(text[i]==='d'&&text[i+1]==='/'&&text[i+2]==='d'){
            variable=text[i+3];
            i+=4;
        }
        else if(text[i]===variable){
            hit=true;
            continue;
        }
        else if(ispower){
            power*=10;
            power+=parseInt(text[i]);
        }
        else if(text[i]==='-'){
            neg=true;
        }
        else if(text[i]==='+'){
            neg=false;
        }
        else if(text[i]==='1'||text[i]==='0'||text[i]==='2'||text[i]==='3'||text[i]==='4'||text[i]==='5'||text[i]==='6'||text[i]==='7'||text[i]==='8'||text[i]==='9'){
            coeff*=10;
            coeff+=parseInt(text[i]);
        }
    }
    div.innerHTML = output;
}
