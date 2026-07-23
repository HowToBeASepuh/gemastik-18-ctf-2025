function main(){
    const url = (new URL(location)).searchParams
    if (url.has("svg")){
        const svg = document.querySelector("svg")
        svg.innerHTML = url.get("svg")
    }
}

main()