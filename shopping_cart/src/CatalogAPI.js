const handleResponse = (response, callback, key = 'data') => {
    // console.log(response)
    // success
    if(response.status && response.status === 200 && !response.error) callback(response[key], 'success')
    // success response array
    else if(Array.isArray(response)) callback(response, 'success')
    // error
    else {
        if(response.error && !response.message){
            if(response.error.message){
                let err_msg = response.error.message
                if(response.error.errors){
                    Object.keys(response.error.errors).forEach(key => {
                        err_msg += '. ' + response.error.errors[key]
                    })
                }
                callback(err_msg, 'error')
            }
            else callback(response.error, 'error')
        }
        if(response.error && response.message) callback(response.message, 'error')
    }
}


const sendNetworkRequest = (url, method, headers, body, cbk, response_key = 'data') => {
    fetch(url, {
        method: method,
        headers: headers || {},
        body: body
    }).then(r => r.json()).then(r => {
        handleResponse(r, cbk, response_key)
    }).catch(e => {
        console.error(e.message)
        cbk(e.message, 'error')
    })
}

const base_url = process.env.REACT_APP_api_base_url;
console.log(base_url)

export const getGenres = (input, callback) => {
    sendNetworkRequest(base_url + '/genres', 'GET', {'Content-type': 'application/x-www-form-urlencoded'}, null, callback, 'data')   
}
export const getArtists = (input, callback) => {
    const url = `${base_url}/artists${(input && input.length) ? input : ''}`
    sendNetworkRequest(url, 'GET', {'Content-type': 'application/x-www-form-urlencoded'}, null, callback, 'data')   
}
export const getAlbums = (input, callback) => {
    const url = `${base_url}/albums${(input && input.length) ? input : ''}`
    sendNetworkRequest(url, 'GET', {'Content-type': 'application/x-www-form-urlencoded'}, null, callback, 'data')   
}
export const getSongs = (input, callback) => {
    const url = `${base_url}/songs${(input && input.length) ? input : ''}`
    sendNetworkRequest(url, 'GET', {'Content-type': 'application/x-www-form-urlencoded'}, null, callback, 'data')   
}
export const getCart = (input, callback) => {
    const url = `${base_url}/cart${(input && input.length) ? input : ''}`
    sendNetworkRequest(url, 'GET', {'Content-type': 'application/x-www-form-urlencoded'}, null, callback, 'data')   
}
export const addToCart = (input, callback) => {
    sendNetworkRequest(base_url + '/cart', 'POST', {'Content-type': 'application/json'}, JSON.stringify(input), callback, 'message')   
}
export const purchaseCart = (input, callback) => {
    sendNetworkRequest(base_url + '/cart', 'PUT', {'Content-type': 'application/json'}, null, callback, 'message')   
}
export const removeCartItem = (input, callback) => {
    sendNetworkRequest(base_url + '/cart', 'DELETE', {'Content-type': 'application/json'}, JSON.stringify(input), callback, 'message')   
}