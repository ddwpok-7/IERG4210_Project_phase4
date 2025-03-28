let cart = [];
let isIndexPage = window.location.pathname.includes('index.html');
let isProductPage = window.location.pathname.includes('product.html');
let isAdminPage = window.location.pathname.includes('admin.html');

function debounce(func, wait) {
    let timeout;
    return function (...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}

// Check authentication status (for non-login pages)
async function checkAuthStatus() {
    try {
      const response = await fetch('http://localhost:3000/check-auth', {
        credentials: 'include',
      });
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
      const data = await response.json();
      const loginButton = document.getElementById('login-button');
      const userDisplay = document.getElementById('user-display');
  
      if (data.authenticated) {
        if (data.isAdmin) {
          loginButton.innerHTML = 'Admin Panel';
          loginButton.onclick = () => window.location.href = 'admin.html';
        } else {
          loginButton.innerHTML = 'Change Password';
          loginButton.onclick = () => window.location.href = 'login.html';
        }
        userDisplay.textContent = data.email; // Show logged-in user's email
      } else {
        loginButton.innerHTML = '<a href="login.html">Login</a>';
        loginButton.onclick = null;
        userDisplay.textContent = 'Guest'; // Show "guest" when not logged in
      }
    } catch (error) {
      console.error('Error checking auth status:', error);
    }
}

window.onload = async function() {
    const params = new URLSearchParams(window.location.search);
    const catid = params.get('catid') || 1;
    const pid = params.get('pid');
    
    await checkAuthStatus();
    loadCart();
    loadCategories();

    if (isIndexPage) {
        loadProducts(catid);
        loadPath(catid);
    }

    if (isProductPage) {
        loadProductDetails(pid);
        loadPath(catid);
        loadProductPath(pid);
    }

    if (isAdminPage) {
        loadCategoriesAddSelect();
        loadProductsUpdateSelect();
        loadProductsDeleteSelect(); 

        /* const response = await fetch('http://localhost:3000/check-auth', { credentials: 'include' });
        const data = await response.json();
        if (!data.authenticated || !data.isAdmin) {
            window.location.href = 'login.html';
        } else {
            loadCategoriesAddSelect();
            loadProductsUpdateSelect();
            loadProductsDeleteSelect();
        } */
    }
};

function fetchProductDetails(pid) {
    return fetch(`http://localhost:3000/getProductDetails?pid=${pid}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to fetch product details');
            }
            return response.json();
        });
}

/*function addToCart(pid) {
    const item = cart.find(product => product.pid === pid);
    if (item) {
        item.quantity++;
    } else {
        cart.push({ pid, quantity: 1 });
    }
    updateCart();
}*/

const addToCart = debounce(function(pid) {
    const item = cart.find(product => product.pid === pid);
    if (item) {
        item.quantity++;
    } else {
        cart.push({ pid, quantity: 1 });
    }
    updateCart();
}, 300);

function removeFromCart(pid) {
    cart = cart.filter(product => product.pid !== pid);
    updateCart();
}

function updateQuantity(pid, quantity) {
    const item = cart.find(product => product.pid === pid);
    if (item) {
        item.quantity = quantity;
        if (quantity <= 0) {
            removeFromCart(pid);
        } else {
            updateCart();
        }
    }
}

function updateCart() {
    const cartItems = document.getElementById('cart-items');
    const cartTotal = document.getElementById('cart-total');
    cartItems.innerHTML = '';
    let total = 0;

    const productPromises = cart.map(item => fetchProductDetails(item.pid));

    Promise.all(productPromises)
        .then(products => {
            products.forEach((product, index) => {
                const li = document.createElement('li');

                li.textContent = `${product.name} - $${product.price}\u00A0`;

                const quantityContainer = document.createElement('div');

                const incrementButton = document.createElement('button');
                incrementButton.textContent = '+';
                incrementButton.onclick = () => updateQuantity(cart[index].pid, cart[index].quantity + 1);
                quantityContainer.appendChild(incrementButton);

                const quantityInput = document.createElement('input');
                quantityInput.type = 'number';
                quantityInput.value = cart[index].quantity;
                quantityInput.min = '0';
                quantityInput.style.width = '50px';
                quantityInput.style.textAlign = 'center';
                quantityInput.onchange = () => updateQuantity(cart[index].pid, parseInt(quantityInput.value));
                quantityContainer.appendChild(quantityInput);

                const decrementButton = document.createElement('button');
                decrementButton.textContent = '-';
                decrementButton.onclick = () => updateQuantity(cart[index].pid, cart[index].quantity - 1);
                quantityContainer.appendChild(decrementButton);

                li.appendChild(quantityContainer);

                const productPrice = cart[index].quantity * product.price;
                li.appendChild(document.createTextNode(`\u00A0= $${productPrice.toFixed(2)}`));

                cartItems.appendChild(li);
                total += productPrice;
            });
            cartTotal.textContent = `Total: $${total.toFixed(2)}`;
            saveCart();
        })
        .catch(error => {
            console.error('Error fetching product details:', error);
        });
}

function saveCart() {
    localStorage.setItem('cart', JSON.stringify(cart));
}

function loadCart() {
    const storedCart = localStorage.getItem('cart');
    if (storedCart) {
        cart = JSON.parse(storedCart);
        updateCart();
    }
}

function clearCart() {
  localStorage.removeItem('cart');
  cart.length = 0;
  updateCart();
}

function loadCategoriesAddSelect() {
    fetch('http://localhost:3000/')
        .then(response => response.json())
        .then(categories => {
            console.log('Categories:', categories);
            const categorySelect = document.getElementById('category-add-select');
            console.log('Category Select Element:', categorySelect);
            categories.forEach(category => {
                const option = document.createElement('option');
                option.value = category.catid;
                option.textContent = category.name;
                categorySelect.appendChild(option);
            });
        })
        .catch(error => console.error('Error fetching categories:', error));
}

function loadProductsUpdateSelect() {
    fetch('http://localhost:3000/productList')
        .then(response => response.json())
        .then(products => {
            console.log('Fetched products:', products);
            const productSelect = document.getElementById('product-update-select');
            products.forEach(product => {
                const option = document.createElement('option');
                option.value = product.pid;
                option.textContent = product.name;
                productSelect.appendChild(option);
            });
        })
        .catch(error => console.error('Error fetching products:', error));
}

function loadProductsDeleteSelect() {
    fetch('http://localhost:3000/productList')
        .then(response => response.json())
        .then(products => {
            console.log('Fetched products:', products);
            const productSelect = document.getElementById('product-delete-select');
            products.forEach(product => {
                const option = document.createElement('option');
                option.value = product.pid;
                option.textContent = product.name;
                productSelect.appendChild(option);
            });
        })
        .catch(error => console.error('Error fetching products:', error));
}

function loadCategories() {
    fetch('http://localhost:3000/')
        .then(response => response.json())
        .then(categories => {
            const categoryList = document.getElementById('category-list');
            categoryList.innerHTML = '';
            categories.forEach(category => {
                const li = document.createElement('li');
                li.innerHTML = `<a href="index.html?catid=${category.catid}" onclick="loadProducts(${category.catid}), loadPath(${category.catid})">&nbsp;${category.name}&nbsp;</a>`;
                categoryList.appendChild(li);
            });
        })
        .catch(error => console.error('Error fetching categories:', error));
}

function loadPath(catid) {
    fetch(`http://localhost:3000/categories?catid=${catid}`)
        .then(response => response.json())
        .then(categories => {
            console.log('Fetched category:', categories);
            const navigationPath = document.getElementById('navigation-path');
            navigationPath.innerHTML = '';
            categories.forEach(category => {
                const li = document.createElement('li');
                li.innerHTML = `<a href="index.html?catid=${category.catid}">${category.name}</a>`;
                navigationPath.appendChild(li);
            });
        })
        .catch(error => console.error('Error fetching categories:', error));
}

function loadProductPath(pid) {
    fetch(`http://localhost:3000/productPath?pid=${pid}`)
        .then(response => response.json())
        .then(products => {
            console.log('Fetched product Path:', products);
            const navigationPath = document.getElementById('navigation-product-path');
            navigationPath.innerHTML = '';
            products.forEach(product => {
                const li = document.createElement('li');
                li.innerHTML = `<a href="product.html?catid=${product.catid}&pid=${product.pid}">${product.name}</a>`;
                navigationPath.appendChild(li);
            });
        })
        .catch(error => console.error('Error fetching product:', error));
}

function loadProducts(catid) {
    fetch(`http://localhost:3000/products?catid=${catid}`)
        .then(response => response.json())
        .then(products => {
            const productList = document.getElementById('product-list');
            productList.innerHTML = '';
            products.forEach(product => {
                const div = document.createElement('div');
                div.className = 'product';
                div.innerHTML = `
                    <a href="product.html?catid=${product.catid}&pid=${product.pid}">
                        <img src="uploads/${product.image_url}" alt="${product.name}">
                        <h3>${product.name}</h3>
                    </a>
                    <p>$${product.price}</p>
                    <button class="add-to-cart" onclick="addToCart('${product.pid}')">Add to Cart</button>
                `;
                productList.appendChild(div);
            });
        })
        .catch(error => console.error('Error fetching products:', error));
}

function loadProductDetails(pid) {
    fetch(`http://localhost:3000/productInformation?pid=${pid}`)
        .then(response => response.json())
        .then(products => {
            const productDetails = document.getElementById('product-description');
            productDetails.innerHTML = '';
            products.forEach(product => {
                console.log('Fetched product:', product);
                const section = document.createElement('section');
                section.className = 'productlayout';
                section.innerHTML = `
                    <div class="product-image">
                        <img src="uploads/${product.image_url}" alt="${product.name}">
                    </div>

                    <div class="product-description">
                        <h2>${product.name}</h2>
                        <p>${product.description}</p>
                        <p class="price">${product.price}</p>

                        <button class="add-to-cart" onclick="addToCart('${product.pid}')">Add to Cart</button>
                    </div>
                `;
                productDetails.appendChild(section);
            });
        })
        .catch(error => {
            console.error('Error fetching product:', error);
            alert('Error loading product information: ' + error.message); // Display the error in an alert
        });
}

function validateImage(inputID, errorID) {
    const fileInput = document.getElementById(inputID);
    const errorMessage = document.getElementById(errorID);
    const file = fileInput.files[0];
    errorMessage.textContent = '';

    if (file) {
        const maxSize = 10 * 1024 * 1024; // 10MB
        if (file.size > maxSize) {
            errorMessage.textContent = 'Image size must be 10MB or less.';
            fileInput.value = '';
            return;
        }

        const validTypes = ['image/jpeg', 'image/gif', 'image/png'];
        if (!validTypes.includes(file.type)) {
            errorMessage.textContent = 'Invalid file type. Please upload a JPG, GIF, or PNG image.';
            fileInput.value = '';
            return;
        }
    }
}