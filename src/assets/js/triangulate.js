function createOverlay() {
    var overlay = document.createElement("div");
    overlay.id = "game-overlay";
    overlay.style.position = "fixed";
    overlay.style.top = "0";
    overlay.style.left = "0";
    overlay.style.width = "100%";
    overlay.style.height = "100%";
    overlay.style.backgroundColor = "rgba(0, 0, 0, 0.5)";
    overlay.style.display = "flex";
    overlay.style.justifyContent = "center";
    overlay.style.alignItems = "center";
    overlay.style.zIndex = "9999";

    var rules = document.createElement("div");
    rules.style.backgroundColor = "#222";
    rules.style.padding = "20px";
    rules.style.borderRadius = "5px";
    rules.style.textAlign = "center";
    rules.style.border = "2px solid #741f22";
    rules.style.boxShadow = "0 0 10px #741f22";

    var title = document.createElement("h2");
    title.textContent = "Game Rules";
    title.style.fontFamily = "Arial, sans-serif";
    title.style.fontSize = "24px";
    title.style.fontWeight = "bold";
    title.style.color = "#ff434a";
    title.style.textShadow = "2px 2px 4px #000000";
    title.style.marginBottom = "20px";

    var rule1 = document.createElement("p");
    rule1.textContent = "1. You will be shown a triangle.";
    rule1.style.fontFamily = "Arial, sans-serif";
    rule1.style.fontSize = "16px";
    rule1.style.textAlign = "left";
    rule1.style.marginLeft = "20px";
    rule1.style.color = "#ff434a";
    rule1.style.marginBottom = "10px";

    var rule2 = document.createElement("p");
    rule2.textContent = "2. Your task is to click on the point that corresponds to the given center (centroid, circumcenter, incenter, or orthocenter).";
    rule2.style.fontFamily = "Arial, sans-serif";
    rule2.style.fontSize = "16px";
    rule2.style.textAlign = "left";
    rule2.style.marginLeft = "20px";
    rule2.style.color = "#ff434a";
    rule2.style.marginBottom = "10px";

    var rule3 = document.createElement("p");
    rule3.textContent = "3. Your score will be calculated based on the time taken and the distance from the correct center. Accuracy is weighed higher than speed, the formula is (2*time + 3*accuracy)/5.";
    rule3.style.fontFamily = "Arial, sans-serif";
    rule3.style.fontSize = "16px";
    rule3.style.textAlign = "left";
    rule3.style.marginLeft = "20px";
    rule3.style.color = "#ff434a";
    rule3.style.marginBottom = "20px";

    var startButton = document.createElement("button");
    startButton.id = "start-button";
    startButton.textContent = "Start Game";
    startButton.style.fontFamily = "Arial, sans-serif";
    startButton.style.fontSize = "16px";
    startButton.style.marginRight = "10px";
    startButton.classList.add("btn", "btn-info");
    startButton.addEventListener("click", function() {
        overlay.style.display = "none";
    });

    var backButton = document.createElement("button");
    backButton.textContent = "Go Back";
    backButton.style.fontFamily = "Arial, sans-serif";
    backButton.style.fontSize = "16px";
    backButton.classList.add("btn", "btn-secondary");
    backButton.addEventListener("click", function() {
        overlay.style.display = "none";
    });

    rules.appendChild(title);
    rules.appendChild(rule1);
    rules.appendChild(rule2);
    rules.appendChild(rule3);
    rules.appendChild(startButton);
    rules.appendChild(backButton);

    overlay.appendChild(rules);

    document.body.appendChild(overlay);

    function startCountdown(pre_text, seconds) {
        var countdownOverlay = document.createElement("div");
        countdownOverlay.id = "countdown-overlay";
        countdownOverlay.style.position = "fixed";
        countdownOverlay.style.top = "0";
        countdownOverlay.style.left = "0";
        countdownOverlay.style.width = "100%";
        countdownOverlay.style.height = "100%";
        countdownOverlay.style.backdropFilter = "blur(7px)";
        countdownOverlay.style.display = "flex";
        countdownOverlay.style.justifyContent = "center";
        countdownOverlay.style.alignItems = "center";
        countdownOverlay.style.zIndex = "9999";
        countdownOverlay.style.transition = "opacity 0.5s ease-in"; // Add transition for fade effect
    
        var countdownText = document.createElement("div");
        countdownText.style.fontFamily = "Arial, sans-serif";
        countdownText.style.fontSize = "48px";
        countdownText.style.fontWeight = "bold";
        countdownText.style.color = "black!important";
        countdownText.style.textShadow = "0 0 5px black";
        countdownText.textContent = pre_text + seconds.toFixed(1); // Initial countdown value with 1/10th of seconds
        countdownOverlay.appendChild(countdownText);
    
        document.body.appendChild(countdownOverlay);
    
        // Countdown timer
        var count = seconds;
        var countdownInterval = setInterval(function() {
            count -= 0.01;
            if (count < 0) {
                count = 0;
            }
            countdownText.textContent = pre_text + count.toFixed(2).toString() + "s";
            if (count <= 0) {
                clearInterval(countdownInterval);
                countdownOverlay.style.opacity = "0"; // Start fading out
                setTimeout(function() {
                    countdownOverlay.style.display = "none";
                }, 500);
            }
        }, 10);
    }

    document.querySelector("#start-button").addEventListener("click", function() {
        document.querySelector("#start-game").style.display = "none";
        document.querySelector("#game-overlay").style.display = "none";
        document.querySelector("#lb-btn").style.display = "none";
        document.querySelector("#game-div").classList.remove("hidden");
        startCountdown("Game Starting In ", 5);
        window.scrollTo(0, document.body.scrollHeight);
        setTimeout(function() {
            var canvas;
            var ax, bx, cx;
            var ay, by, cy;
            var sides, area;
            var cursorX = -1, cursorY;
            var centerX, centerY;
            var level = 0;
            var score = 0;
            var best = -1;
            var canClick = true;
            var timestamp;
            const text = ["centroid","circumcenter","incenter","orthocenter"];
            const explanation = [
                "The centroid is the intersection of the medians of the triangle. It can be seen as an average of the vertices of the triangle.",
                "The circumcenter is the center of the circle passing through all the vertices of the triangle. It is also the intersection of the perpendicular bisectors of the sides.",
                "The incenter is the center of the circle tangent to all the sides of the triangle. It is also the intersection of the angle bisectors.",
                "The orthocenter is the intersection of the 3 altitudes of the triangle."
            ];
            const width = 250;
            const height = 250;
            var cc = document.getElementById("game");
            cc.style.width = width;
            cc.style.height = height;
            function createTriangle(){
                ax = Math.floor(Math.random()*width); //stupidest code i've ever written
                bx = Math.floor(Math.random()*width);
                cx = Math.floor(Math.random()*width);
                ay = Math.floor(Math.random()*height);
                by = Math.floor(Math.random()*height);
                cy = Math.floor(Math.random()*height);
                area = Math.abs(ax*by+bx*cy+cx*ay-(ay*bx+by*cx+cy*ax))/2;
                if(area < 10000 || area > 12500){
                    return 0;
                }
                sides = Array(Math.sqrt((cx-bx)*(cx-bx)+(cy-by)*(cy-by)),
                                    Math.sqrt((ax-cx)*(ax-cx)+(ay-cy)*(ay-cy)),
                                    Math.sqrt((bx-ax)*(bx-ax)+(by-ay)*(by-ay)));
                centerX = Array((ax+bx+cx)/3,
                                0.5*((ax*ax+ay*ay)*(by-cy)+(bx*bx+by*by)*(cy-ay)+(cx*cx+cy*cy)*(ay-by))/(ax*(by-cy)+bx*(cy-ay)+cx*(ay-by)),
                                (sides[0]*ax+sides[1]*bx+sides[2]*cx)/(sides[0]+sides[1]+sides[2]),
                                0);
                centerX[3] = ax+bx+cx-2*centerX[1];
                centerY = Array((ay+by+cy)/3,
                                0.5*((ax*ax+ay*ay)*(bx-cx)+(bx*bx+by*by)*(cx-ax)+(cx*cx+cy*cy)*(ax-bx))/(ay*(bx-cx)+by*(cx-ax)+cy*(ax-bx)),
                                (sides[0]*ay+sides[1]*by+sides[2]*cy)/(sides[0]+sides[1]+sides[2]),
                                (bx-cx)/(cy-by)*(centerX[3]-ax)+ay);
                centerY[3] = ay+by+cy-2*centerY[1];
                for(var i = 0; i<3; ++i){ //Restrict max angle
                    if((sides[i]*sides[i]-sides[(i+1)%3]*sides[(i+1)%3]-sides[(i+2)%3]*sides[(i+2)%3])/(2*sides[(i+1)%3]*sides[(i+2)%3])<-0.8){
                        return 0;
                    }
                }
                for(var i = 0; i<4; ++i){ //make sure the centers are in the canvas
                    if(centerX[i]<0 || centerX[i]>width || centerY[i]<0 || centerY[i]>height){
                        return 0;
                    }
                } return 1;
            }
        
            function drawTriangle(){
                canvas.moveTo(ax,ay);
                canvas.lineTo(bx,by);
                canvas.lineTo(cx,cy);
                canvas.lineTo(ax,ay);
                canvas.stroke();
            }
        
            function drawPoint(pointX, pointY, colour){
                canvas.arc(pointX,pointY,5,0,2*Math.PI);
                canvas.fillStyle = colour;
                canvas.fill();
                canvas.stroke();
            }
        
            function takeSub(){
                if(cursorX<0){return;}
                canClick = false;
                if(level >= 3) {
                    document.getElementById("submit").classList.remove("hidden");
                    document.getElementById("submit").innerHTML = "Play again (unrated)";
                }  const timeDiff = (Date.now()-timestamp)/1000;
                const distance = Math.sqrt((centerX[level]-cursorX)*(centerX[level]-cursorX)+(centerY[level]-cursorY)*(centerY[level]-cursorY));
                score += ((timeDiff*2+distance*3)/5)*(10000/area);
                document.getElementById("current").innerHTML = "Your current score: "+ score.toFixed(2);
                if((score<best || best<0) && level==3){
                    best = score;
                    document.getElementById("best").innerHTML = "Your best score: "+best.toFixed(2);
                }
                document.getElementById("stats").innerHTML = "You took " + timeDiff.toFixed(2) + " seconds and your distance from the " + text[level] + " was " + distance.toFixed(2) + " units.";
                canvas.clearRect(0,0,width,height);
                canvas.beginPath();
                switch(level){
                    case 0:
                        canvas.moveTo(ax,ay);
                        canvas.lineTo((bx+cx)/2,(by+cy)/2);
                        canvas.moveTo(bx,by);
                        canvas.lineTo((ax+cx)/2,(ay+cy)/2);
                        canvas.moveTo(cx,cy);
                        canvas.lineTo((bx+ax)/2,(by+ay)/2);
                        break;
                    case 1:
                        canvas.arc(centerX[1],centerY[1],sides[0]*sides[1]*sides[2]/(4*area),0,2*Math.PI);
                        canvas.moveTo((ax+bx)/2,(ay+by)/2);
                        canvas.lineTo(centerX[1],centerY[1]);
                        canvas.moveTo((bx+cx)/2,(by+cy)/2);
                        canvas.lineTo(centerX[1],centerY[1]);
                        canvas.moveTo((cx+ax)/2,(cy+ay)/2);
                        canvas.lineTo(centerX[1],centerY[1]);
                        break;
                    case 2:
                        canvas.arc(centerX[2],centerY[2],area*2/(sides[0]+sides[1]+sides[2]),0,2*Math.PI);
                        canvas.moveTo(ax,ay);
                        canvas.lineTo(sides[2]/(sides[1]+sides[2])*(cx-bx)+bx,sides[2]/(sides[1]+sides[2])*(cy-by)+by);
                        canvas.moveTo(bx,by);
                        canvas.lineTo(sides[0]/(sides[2]+sides[0])*(ax-cx)+cx,sides[0]/(sides[2]+sides[0])*(ay-cy)+cy);
                        canvas.moveTo(cx,cy);
                        canvas.lineTo(sides[1]/(sides[0]+sides[1])*(bx-ax)+ax,sides[1]/(sides[0]+sides[1])*(by-ay)+ay);
                        break;
                    case 3:
                        var cax = (by-(cy-by)/(cx-bx)*bx+(bx-cx)/(cy-by)*ax-ay)/((bx-cx)/(cy-by)-(cy-by)/(cx-bx)); //why
                        var cay = (cy-by)/(cx-bx)*(cax-bx)+by;
                        var cbx = (ay-(cy-ay)/(cx-ax)*ax+(ax-cx)/(cy-ay)*bx-by)/((ax-cx)/(cy-ay)-(cy-ay)/(cx-ax));
                        var cby = (cy-ay)/(cx-ax)*(cbx-ax)+ay;
                        var ccx = (by-(ay-by)/(ax-bx)*bx+(bx-ax)/(ay-by)*cx-cy)/((bx-ax)/(ay-by)-(ay-by)/(ax-bx));
                        var ccy = (ay-by)/(ax-bx)*(ccx-bx)+by;
                        canvas.moveTo(ax,ay);
                        canvas.lineTo(cax,cay);
                        canvas.lineTo(centerX[3],centerY[3]);
                        canvas.moveTo(bx,by);
                        canvas.lineTo(cbx,cby);
                        canvas.lineTo(centerX[3],centerY[3]);
                        canvas.moveTo(cx,cy);
                        canvas.lineTo(ccx,ccy);
                        canvas.lineTo(centerX[3],centerY[3]);
                        canvas.stroke();
                        canvas.setLineDash([2,4]);
                        canvas.moveTo(bx,by);
                        canvas.lineTo(cax,cay);
                        canvas.moveTo(cx,cy);
                        canvas.lineTo(cbx,cby);
                        canvas.moveTo(ax,ay);
                        canvas.lineTo(ccx,ccy);
                        break;
                }
                canvas.stroke();
                canvas.setLineDash([]);
                canvas.closePath();
                canvas.beginPath();
                drawPoint(cursorX,cursorY,"rgb(255,0,0)");
                canvas.closePath();
                canvas.beginPath();
                drawPoint(centerX[level],centerY[level],"rgb(0,255,0)");
                drawTriangle();
            }
        
            function nextLevel() {
                if (level < 3) {
                    startCountdown("Next Level In ", 3);
                    setTimeout(function() {
                        canClick = true;
                        if (level == 3) {
                            var success = createTriangle();
                            score = 0;
                            document.getElementById("current").innerHTML = "Your current score: 0";
                        }
                        level++;
                        document.getElementById("text").innerHTML = "Find the location of the " + text[level] + "!";
                        document.getElementById("explanation").innerHTML = explanation[level];
                        canvas.clearRect(0, 0, width, height);
                        canvas.beginPath();

                        // Flash countdown
                        drawTriangle();
                        cursorX = -1;
                        timestamp = Date.now();
                    }, 3500);
                } else {
                    var overlay = document.createElement("div");
                    overlay.style.position = "fixed";
                    overlay.style.top = "0";
                    overlay.style.left = "0";
                    overlay.style.width = "100%";
                    overlay.style.height = "100%";
                    overlay.style.backgroundColor = "rgba(0, 0, 0, 0.5)";
                    overlay.style.display = "flex";
                    overlay.style.justifyContent = "center";
                    overlay.style.alignItems = "center";
                    overlay.style.zIndex = "9999";

                    var overlayContent = document.createElement("div");
                    overlayContent.style.backgroundColor = "white";
                    overlayContent.style.padding = "40px";
                    overlayContent.style.borderRadius = "10px";
                    overlayContent.style.textAlign = "center";

                    var scoreText = document.createElement("p");
                    scoreText.style.fontSize = "48px";
                    scoreText.innerHTML = "Your score: " + score.toFixed(2);

                    var okButton = document.createElement("button");
                    okButton.classList.add("btn", "btn-lg", "btn-outline-info");
                    okButton.style.fontSize = "30px";
                    okButton.innerHTML = "OK";
                    okButton.addEventListener("click", function() {
                        // Create a form element
                        var form = document.querySelector("#game-submit");

                        // Create an input field for the score
                        var scoreInput = document.createElement("input");
                        scoreInput.type = "hidden";
                        scoreInput.name = "score";
                        scoreInput.value = score.toFixed(2); // Assuming "score" is a variable holding the score value

                        // Append the input field to the form
                        form.appendChild(scoreInput);
                        // Submit the form
                        form.submit();
                    });

                    overlayContent.appendChild(scoreText);
                    overlayContent.appendChild(okButton);
                    overlay.appendChild(overlayContent);
                    document.body.appendChild(overlay);
                }
            }
        
            function timer(){
                if(canClick){
                    document.getElementById("stats").innerHTML = "Your time: " + ((Date.now()-timestamp)/1000).toFixed(2);
                }
            }
        
            canvas = cc.getContext("2d");
            var success = createTriangle();
            while (success == 0) {
                success = createTriangle();
            }
            drawTriangle();
            timestamp = Date.now();
            setInterval(timer,10);
        
            const ctx = document.querySelector('canvas');
            ctx.addEventListener('mousedown',function(event){
                if(!canClick){return;}
                const rect = ctx.getBoundingClientRect();
                cursorX = event.clientX - rect.left;
                cursorY = event.clientY - rect.top;
                canvas.clearRect(0,0,width,height);
                canvas.beginPath();
                drawPoint(cursorX,cursorY,"rgb(255,0,0)");
                drawTriangle();
                takeSub();
                nextLevel();
            });
        }, 5500);
    });
}


document.querySelector("#start-game").addEventListener("click", function() {
    createOverlay();
});