// Test email uniqueness
it('should not allow duplicate emails', async () => {
    const user1 = new User({
        name: 'User 1',
        email: 'duplicate@example.com', 
        password: 'password123'
    });

    const user2 = new User({
        name: 'User 2',
        email: 'duplicate@example.com',
        password: 'password456'
    });

    await user1.save();

    try {
        await user2.save();
        assert.fail('Should have thrown duplicate email error');
    } catch (error) {
        assert(error.code === 11000); // MongoDB duplicate key error
    }
});

// Test password hashing
it('should hash the password before saving', async () => {
    const user = new User({
        name: 'Hash Test',
        email: 'hash@example.com',
        password: 'password123'
    });

    await user.save();
    assert(user.password !== 'password123');
    
    const isMatch = await bcrypt.compare('password123', user.password);
    assert(isMatch === true);
});

// Test refresh tokens
it('should properly manage refresh tokens', async () => {
    const user = new User({
        name: 'Token Test',
        email: 'token@example.com',
        password: 'password123'
    });

    await user.save();
    
    user.refreshTokens.push('token1');
    user.refreshTokens.push('token2');
    await user.save();

    const foundUser = await User.findOne({email: 'token@example.com'});
    assert(foundUser.refreshTokens.length === 2);
    assert(foundUser.refreshTokens.includes('token1'));
    assert(foundUser.refreshTokens.includes('token2'));
});

// Test invalid email format
it('should validate email format', async () => {
    const user = new User({
        name: 'Email Test',
        email: 'notanemail',
        password: 'password123'
    });

    try {
        await user.save();
        assert.fail('Should have rejected invalid email');
    } catch (error) {
        assert(error.errors.email);
    }
});

// Test name length validation
it('should validate minimum name length', async () => {
    const user = new User({
        name: 'A',
        email: 'short@example.com',
        password: 'password123'
    });

    try {
        await user.save();
        assert.fail('Should have rejected short name');
    } catch (error) {
        assert(error.errors.name);
    }
});

// Test todo creation
it('should create a new todo', async () => {
    const user = await createTestUser();
    const token = generateAccessToken(user._id);
    
    const response = await request(app)
        .post('/todos')
        .set('Authorization', `Bearer ${token}`)
        .send({
            title: 'Test Todo',
            description: 'Test Description',
            priority: 'high'
        });
    
    assert(response.status === 201);
    assert(response.body.title === 'Test Todo');
});

// Test rate limiting
it('should enforce rate limits', async () => {
    const user = await createTestUser();
    const token = generateAccessToken(user._id);
    
    // Make more requests than the limit allows
    for(let i = 0; i <= 100; i++) {
        await request(app)
            .get('/todos')
            .set('Authorization', `Bearer ${token}`);
    }
    
    const response = await request(app)
        .get('/todos')
        .set('Authorization', `Bearer ${token}`);
        
    assert(response.status === 429); // Too Many Requests
});

// Helper function for tests
async function createTestUser() {
    return await User.create({
        name: 'Test User',
        email: `test${Date.now()}@example.com`,
        password: await bcrypt.hash('password123', 10)
    });
}